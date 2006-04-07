/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved. 
 * 
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED 
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT 
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 * 
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

#include "lwip/opt.h"

#include "lwip/sys.h"

#include "lwip/memp.h"
#include "lwip/pbuf.h"

#include "lwip/ip.h"
#include "lwip/udp.h"
#include "lwip/tcp.h"

#include "lwip/tcpip.h"

/*---------------------------------------------------------------------------*/

/*
 * The idea is to run the stack code in a different thread and
 * to comunicate with it (or shutdown it) by using messages.
 * After tcpip_shutdown() any call has no effect.
 * 
 * 	main thread             tcpip_thread
 * 	  |
 * 	  |
 * 	tcpip_init()--------------> *new*
 * 	  |                           |
 * 	 ...                         ...
 * 	tcpip_input()......msg......> |
 * 	tcpip_input()......msg......> |
 * 	 ...                         ...
 * 	  |                           |
 * 	tcpip_shutdown().....msg....> |
 * 	  |                           *
 *      tcpip_input() 
 * 	  |
 * 	exit()
 */

/* called after stack initialization */
static void (* tcpip_init_done)(void *arg) = NULL;
static void *tcpip_init_done_arg;

/* called before stack thread termination  */
static void (* tcpip_shutdown_done)(void *arg) = NULL;
static void *tcpip_shutdown_done_arg;

/* 1 = tcpip_thread is running, 0 = shutting down */
static u8_t  tcpip_mainthread_run = 0;
sys_sem_t    tcpip_mutex;  /* Protect  tcpip_mainthread_run variabile */

/* Stack message queue */
static sys_mbox_t mbox;

/*---------------------------------------------------------------------------*/

#if LWIP_TCP
static int tcpip_tcp_timer_active = 0;

static void
tcpip_tcp_timer(void *arg)
{
	(void)arg;
	
	/* call TCP timer handler */
	tcp_tmr();
	/* timer still needed? */
	if (tcp_active_pcbs || tcp_tw_pcbs) {
		/* restart timer */
		sys_timeout(TCP_TMR_INTERVAL, tcpip_tcp_timer, NULL);
	} else {
		/* disable timer */
		tcpip_tcp_timer_active = 0;
	}
}

#if !NO_SYS
void
tcp_timer_needed(void)
{
	/* timer is off but needed again? */
	if (!tcpip_tcp_timer_active && (tcp_active_pcbs || tcp_tw_pcbs)) {
		/* enable and start timer */
		tcpip_tcp_timer_active = 1;
		sys_timeout(TCP_TMR_INTERVAL, tcpip_tcp_timer, NULL);
	}
}
#endif /* !NO_SYS */
#endif /* LWIP_TCP */


static void
tcpip_thread(void *arg)
{
	int loop;
	struct tcpip_msg *msg;
	
	(void)arg;
	
	ip_init();
	
#if LWIP_UDP  
	udp_init();
#endif
#if LWIP_TCP
	tcp_init();
#endif

	/* Now the main thread is ready */
	tcpip_mainthread_run = 1;
	
	if (tcpip_init_done != NULL) {
		tcpip_init_done(tcpip_init_done_arg);
	}

	loop = 1;
	while (loop) {                          /* MAIN Loop */

		//printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");

		LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: waiting4message\n"));
		sys_mbox_fetch(mbox, (void *)&msg);

		if (msg==NULL) {
			//fprintf(stderr,"tcpip NULL MSG, this should not happen!\n");
			printf("tcpip NULL MSG, this should not happen!\n");
		} else {

			switch (msg->type) {
				case TCPIP_MSG_INPUT:
					LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: IP packet %p\n", (void *)msg));
					ip_input(msg->msg.inp.p, msg->msg.inp.netif);
					break;

				case TCPIP_MSG_API:
					LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: API message %p %p\n", (void *)msg, (void *)msg->msg.apimsg));
					api_msg_input(msg->msg.apimsg);
					break;

				case TCPIP_MSG_CALLBACK:
					LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: CALLBACK %p\n", (void *)msg));
					msg->msg.cb.f(msg->msg.cb.ctx);
					break;

				case TCPIP_MSG_NETIFADD:
					LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: ADD NETIF! %p\n", (void *)msg));

					netif_add(msg->msg.netif.netif,
						msg->msg.netif.state,
						msg->msg.netif.init,
						msg->msg.netif.input);

					/* signal interface creation */
					sys_sem_signal(* msg->msg.netif.sem);   

					break;

				case TCPIP_MSG_SHUTDOWN:
					LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: SHUTDOWN! %p\n", (void *)msg));
					loop = 0;
					break;

				default:
					LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: UNKNOWN MSGTYPE %d\n", msg->type));
					break;
			}
			memp_free(MEMP_TCPIP_MSG, msg);
		}

		//printf("----------------------------------------------------------------------------\n");

	}

	// FIX: this is not enough, after this call netif threads are still alive
	netif_cleanup();

	if (tcpip_shutdown_done != NULL) {
		tcpip_shutdown_done(tcpip_shutdown_done_arg);
	}
}

err_t
tcpip_input(struct pbuf *p, struct netif *inp)
{
	struct tcpip_msg *msg;

	LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip: tcpip_input %p %p\n", (void *)p, (void *) inp));

	// Exit if the main thread is shutting down
	sys_sem_wait_timeout(tcpip_mutex, 0); 
	if (tcpip_mainthread_run == 0) {
		LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip: main thread no more. Exit!\n"));

		pbuf_free(p);

		sys_sem_signal(tcpip_mutex);   
		return ERR_OK;
	}
	

	msg = memp_malloc(MEMP_TCPIP_MSG);
	if (msg == NULL) {
		pbuf_free(p);  
		sys_sem_signal(tcpip_mutex);   
		return ERR_MEM;  
	}
	
	msg->type = TCPIP_MSG_INPUT;
	msg->msg.inp.p = p;
	msg->msg.inp.netif = inp;
	sys_mbox_post(mbox, msg);

	sys_sem_signal(tcpip_mutex);   

	return ERR_OK;
}

err_t
tcpip_callback(void (*f)(void *ctx), void *ctx)
{
	struct tcpip_msg *msg;

	LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip: tcpip_callback %p \n", f));

	// Exit if the main thread is shutting down
	sys_sem_wait_timeout(tcpip_mutex, 0); 
	if (tcpip_mainthread_run == 0) {
		LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip: main thread no more. Exit!\n"));
		sys_sem_signal(tcpip_mutex);   
		return ERR_OK;
	}

	
	msg = memp_malloc(MEMP_TCPIP_MSG);
	if (msg == NULL) {
		sys_sem_signal(tcpip_mutex);
		return ERR_MEM;  
	}
	
	msg->type = TCPIP_MSG_CALLBACK;
	msg->msg.cb.f = f;
	msg->msg.cb.ctx = ctx;
	sys_mbox_post(mbox, msg);

	sys_sem_signal(tcpip_mutex);   

	return ERR_OK;
}

void
tcpip_apimsg(struct api_msg *apimsg)
{
	struct tcpip_msg *msg;

	LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip: tcpip_apimsg %p\n", apimsg));

	// Exit if the main thread is shutting down
	sys_sem_wait_timeout(tcpip_mutex, 0); 
	
	if (tcpip_mainthread_run == 0) {
		LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip: main thread no more. Exit!\n"));

		// FIX: free apimsg? 

		sys_sem_signal(tcpip_mutex);   
		return;
	}

	msg = memp_malloc(MEMP_TCPIP_MSG);
	/*if (msg == NULL) {
	memp_free(MEMP_API_MSG, apimsg);
	return;
	}*/
	while (msg == NULL) {
		sys_msleep(API_MSG_RETRY_DELAY);
		msg = memp_malloc(MEMP_TCPIP_MSG);
	}
	msg->type = TCPIP_MSG_API;
	msg->msg.apimsg = apimsg;
	sys_mbox_post(mbox, msg);

	sys_sem_signal(tcpip_mutex);   
}

/*---------------------------------------------------------------------------*/

void
tcpip_init(void (* initfunc)(void *), void *arg)
{
	tcpip_init_done = initfunc;
	tcpip_init_done_arg = arg;

	mbox = sys_mbox_new();

	tcpip_mutex = sys_sem_new(1);

	sys_thread_new(tcpip_thread, NULL, TCPIP_THREAD_PRIO);
}

void
tcpip_shutdown(void (* shutdown_fun)(void *), void *arg)
{
	struct tcpip_msg *msg;

	LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip: main thread shutdown!\n"));

	sys_sem_wait_timeout(tcpip_mutex, 0); 

	tcpip_shutdown_done = shutdown_fun;
	tcpip_shutdown_done_arg = arg;

	tcpip_mainthread_run = 0;


	// Inform to the thread to shutdown
	msg = memp_malloc(MEMP_TCPIP_MSG);
	if (msg != NULL) {
		msg->type = TCPIP_MSG_SHUTDOWN;
		sys_mbox_post(mbox, msg);
	}

	sys_sem_signal(tcpip_mutex);   
}


struct netif * tcpip_netif_add(struct netif *netif, 
      void *state,
      err_t (* init)(struct netif *netif),
      err_t (* input)(struct pbuf *p, struct netif *netif))
{
	struct tcpip_msg *msg;
	sys_sem_t         msg_wait;

	LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip: main thread shutdown!\n"));

	sys_sem_wait_timeout(tcpip_mutex, 0); 

	msg = memp_malloc(MEMP_TCPIP_MSG);
	if (msg == NULL) {
		sys_sem_signal(tcpip_mutex);
		return NULL;  
	}

	/* Fill message data */	
	msg->type = TCPIP_MSG_NETIFADD;
	msg->msg.netif.netif = netif;
	msg->msg.netif.state = state;
	msg->msg.netif.init  = init;
	msg->msg.netif.input = input;
	msg_wait = sys_sem_new(0);
	msg->msg.netif.sem = &msg_wait;

	sys_mbox_post(mbox, msg);

	/* Make this function syncronous. Wait until interface creation */
	sys_sem_wait_timeout(msg_wait, 0); 
	sys_sem_free(msg_wait);

	sys_sem_signal(tcpip_mutex);   

	return netif;
}




