/*   This is part of LWIPv6
 *   Developed for the Ale4NET project
 *   Application Level Environment for Networking
 *   
 *   Copyright 2005 Diego Billi University of Bologna - Italy
 *   updated:
 *   Copyright 2011 Renzo Davoli University of Bologna - Italy
 *   
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */
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
#include "lwip/debug.h"

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
 * Remember that each interface has its own thread too.
 * 
 * After tcpip_shutdown() any call has no effect.
 * 
 * 	main thread               TCPIP_THREAD           netif thread(s)
 * 	  |
 * 	  |
 * 	tcpip_init()---------------> *new*              
 * 	  |                            |
 * 	tcpip_netif_add()....msg.....> |-------------------> *new*
 * 	  |                            |                       |
 * 	 ...                          ...                     ...
 * 	  |                            | <.......msg...... tcpip_input()
 * 	  |                            | <.......msg...... tcpip_input()
 * 	 ...                          ...                     ...
 * 	  |                            |                       |
 * 	tcpip_shutdown().....msg.....> |                       |
 * 	  |                         netif_cleanup().......> *exit*
 * 	  |                            |
 * 	  |                          *exit*
 *  tcpip_input()
 * 	  |
 * 	exit()
 */

/*---------------------------------------------------------------------------*/

#if LWIP_TCP
static void
tcpip_tcp_timer(void *arg)
{
	struct stack *stack = (struct stack *) arg;
	
	/* call TCP timer handler */
	tcp_tmr(stack);
	
	/* timer still needed? */
	if (stack->tcp_active_pcbs || stack->tcp_tw_pcbs) {
		/* restart timer */
		sys_timeout(TCP_TMR_INTERVAL, tcpip_tcp_timer, (void*)stack);
	} else {
		/* disable timer */
		stack->tcpip_tcp_timer_active = 0;
	}
}

#if !NO_SYS
void
tcp_timer_needed(struct stack *stack)
{
	/* timer is off but needed again? */
	if (!stack->tcpip_tcp_timer_active && 
	    (stack->tcp_active_pcbs || stack->tcp_tw_pcbs)) {
		/* enable and start timer */
		stack->tcpip_tcp_timer_active = 1;
		sys_timeout(TCP_TMR_INTERVAL, tcpip_tcp_timer, (void*)stack);
	}
}
#endif /* !NO_SYS */
#endif /* LWIP_TCP */

/*--------------------------------------------------------------------------*/

static void tcpip_set_down_interfaces(struct stack *stack)
{
	struct netif *nip;
		
	for (nip=stack->netif_list; nip!=NULL; nip=nip->next) {
		ip_notify(nip, NETIF_CHANGE_DOWN);
		netif_set_down_low(nip);
	}
}

/*--------------------------------------------------------------------------*/

static void 
init_layers(struct stack *stack)
{
	netif_init(stack);
	
	ip_init(stack);
	
#if LWIP_UDP  
	udp_init(stack);
#endif
#if LWIP_TCP
	tcp_init(stack);
#endif
}

static void 
shutdown_layers(struct stack *stack)
{
#if LWIP_UDP  
	udp_shutdown(stack);
#endif
#if LWIP_TCP
	tcp_shutdown(stack);
#endif
	/* Handle special transport/network protocol tasks */
	tcpip_set_down_interfaces(stack);

	ip_shutdown(stack);

	netif_shutdown(stack);
}



static void
tcpip_thread(void *arg)
{
	struct stack *stack;
	int loop;
	struct tcpip_msg *msg;
		
	//(void)arg;
	stack = (struct stack *) arg;

	LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: [%d] starting...\n", stack));

	/* Initialize network layers */
	init_layers(stack);


	/* Create stack event queue */
	stack->stack_queue = sys_mbox_new();

	/* Signal tcp_init() function */
	sys_sem_signal(stack->tcpip_init_sem);

	/* Call user defined callback */        
	if (stack->tcpip_init_done != NULL) {
		stack->tcpip_init_done(stack->tcpip_init_done_arg);
	}
	
	LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: [%d] started\n", stack));

	loop = 1;
	while (loop) {                          /* MAIN Loop */

		LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread:  [%d] waiting.\n", stack));
		
		sys_mbox_fetch(stack->stack_queue, (void *)&msg);
		if (msg==NULL) {
			printf("tcpip NULL MSG, this should not happen!\n");
		} else {                    
			switch (msg->type) {
				case TCPIP_MSG_INPUT:
					LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: [%d] IP packet %p\n", stack, (void *)msg));
					ip_input(msg->msg.inp.p, msg->msg.inp.netif);
					break;

				case TCPIP_MSG_API:
					LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: [%d] API message %p %p\n", stack, (void *)msg, (void *)msg->msg.apimsg));
					api_msg_input(msg->msg.apimsg);
					break;

				case TCPIP_MSG_CALLBACK:
					LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: [%d] callback %p\n", stack, (void *)msg));
					msg->msg.cb.f(msg->msg.cb.ctx);
					break;

				case TCPIP_MSG_SYNC_CALLBACK:
					LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: [%d] callback %p\n", stack, (void *)msg));
					msg->msg.cb.f(msg->msg.cb.ctx);
					sys_sem_signal(*msg->msg.cb.sem);
					break;

				case TCPIP_MSG_NETIFADD:
					LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: [%d] add netif %p START\n", stack, (void *)msg));

					*msg->msg.netif.retval = netif_add(stack, msg->msg.netif.netif,
						msg->msg.netif.state,
						msg->msg.netif.init,
						msg->msg.netif.input,
						msg->msg.netif.change);

					/* signal interface creation */
					sys_sem_signal(* msg->msg.netif.sem);   

					LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: [%d] add netif %p DONE!\n", stack, (void *)msg));

					break;

				case TCPIP_MSG_NETIF_NOTIFY:
					LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: [%d] netif state change! %p\n", stack, (void *)msg));

					ip_notify(msg->msg.netif_notify.netif, msg->msg.netif_notify.type);

					sys_sem_signal(* msg->msg.netif_notify.sem);   

					break;

				case TCPIP_MSG_SHUTDOWN:
					LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: [%d] SHUTDOWN! %p\n", stack, (void *)msg));

					loop = 0;
					break;

				default:
					LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: [%d] UNKNOWN MSGTYPE %d\n", stack, msg->type));
					break;
			}
			memp_free(MEMP_TCPIP_MSG, msg);
		}
	}

	LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: [%d] cleaning up interfaces.\n", stack));

	/* Shutdown network layers */
	shutdown_layers(stack);

	/* Call user defined callback */
	if (stack->tcpip_shutdown_done != NULL) {
		stack->tcpip_shutdown_done(stack->tcpip_shutdown_done_arg);
	}

	/* Signal tcp_shutdown() function */
	sys_sem_signal(stack->tcpip_shutdown_sem);

	LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_thread: [%d] exit.\n", stack));
}

/*---------------------------------------------------------------------------*/

static struct stack *current_stack;

int
tcpip_init(void)
{
	current_stack = NULL;

	LWIP_DEBUGF(TCPIP_DEBUG, ("%s: done\n",__func__));
	return 0;
}

static struct stack *tcpip_alloc(void)
{
	int i;

	struct stack *new=mem_malloc(sizeof(struct stack));
	if (new) 
		memset(new,0,sizeof(struct stack));
	return new;
}

static void tcpip_free(struct stack *stack)
{
	mem_free(stack);
}

struct stack *
#if LWIP_CAPABILITIES
tcpip_start(tcpip_handler init_func, void *arg, unsigned long flags,
		lwip_capfun capfun)
#else
tcpip_start(tcpip_handler init_func, void *arg, unsigned long flags)
#endif
{
	struct stack *stack;

	stack = tcpip_alloc();
	if (stack == NULL) {
		LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_start: unable to create a new stack!!\n"));
		return NULL;
	}
	
	LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_start: new stack %d\n",stack));

	stack->tcpip_init_sem      = sys_sem_new(0);
	stack->tcpip_init_done     = init_func;
	stack->tcpip_init_done_arg = arg;
	stack->stack_flags         = flags;
#if LWIP_CAPABILITIES
	stack->stack_capfun        = capfun;
#endif

	sys_thread_new(tcpip_thread, (void*)stack, TCPIP_THREAD_PRIO);

	/* Wait for stack initialization */
	sys_sem_wait(stack->tcpip_init_sem);
	sys_sem_free(stack->tcpip_init_sem);

	LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_start: stack %p running.\n",stack));

	return stack;
}

struct stack *tcpip_stack_get(void)
{
	return current_stack;
}

struct stack *tcpip_stack_set(struct stack * id)
{
	current_stack = id;
	return id;
}

/*---------------------------------------------------------------------------*/

void 
tcpip_shutdown(struct stack *stack, tcpip_handler shutdown_func, void *arg)
{
	struct tcpip_msg *msg;

	LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_shutdown: %d ...\n",stack));

	/* Inform to the thread to shutdown */
	msg = memp_malloc(MEMP_TCPIP_MSG);
	if (msg == NULL) 
		return;

	stack->tcpip_shutdown_sem      = sys_sem_new(0);
	stack->tcpip_shutdown_done     = shutdown_func;
	stack->tcpip_shutdown_done_arg = arg;

	msg->type  = TCPIP_MSG_SHUTDOWN;
	
	sys_mbox_post(stack->stack_queue, msg);

	/* Wait for stack Shutdown */
	sys_sem_wait(stack->tcpip_shutdown_sem);
	sys_sem_free(stack->tcpip_shutdown_sem);

	LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_shutdown: %d stopped.\n",stack));

	/* Stack no more active for sure */
	tcpip_free(stack);
}


/*---------------------------------------------------------------------------*/

err_t
tcpip_callback(struct stack *stack, void (*f)(void *ctx), void *ctx, enum tcpip_sync sync)
{
	struct tcpip_msg *msg;

	/* Check if the stack is valid */
	if (stack==NULL) {
		LWIP_DEBUGF(TCPIP_DEBUG,("%s: stack %d does not exist!\n", __func__, stack));
		return -1;
	}

	LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip: tcpip_callback %p \n", f));

	msg = memp_malloc(MEMP_TCPIP_MSG);
	if (msg == NULL)
		return ERR_MEM;  
	
	msg->msg.cb.f = f;
	msg->msg.cb.ctx = ctx;
	if (sync) {
		sys_sem_t sync;
		msg->type = TCPIP_MSG_SYNC_CALLBACK;
		sync = sys_sem_new(0);
		msg->msg.cb.sem = &sync;
		sys_mbox_post(stack->stack_queue, msg);
		sys_sem_wait_timeout(sync, 0);
		sys_sem_free(sync);
	} else {
		msg->type = TCPIP_MSG_CALLBACK;
		msg->msg.cb.sem = NULL;
		sys_mbox_post(stack->stack_queue, msg);
	}

	return ERR_OK;
}

/*---------------------------------------------------------------------------*/

void
tcpip_apimsg(struct stack *stack, struct api_msg *apimsg)
{
	struct tcpip_msg *msg;

	msg = memp_malloc(MEMP_TCPIP_MSG);
	while (msg == NULL) {
		sys_msleep(API_MSG_RETRY_DELAY);
		msg = memp_malloc(MEMP_TCPIP_MSG);
	}

	msg->type = TCPIP_MSG_API;
	msg->msg.apimsg = apimsg;

	sys_mbox_post(stack->stack_queue, msg);
}
#if 0
/* this should be the right way! a semaphone should be used instead of 
 * NULL smgs! */
void
tcpip_apimsg(struct stack *stack, struct api_msg *apimsg)
{
	struct tcpip_msg msg;
	msg.type = TCPIP_MSG_API;
	msg.msg.apimsg = apimsg;

	sys_mbox_post(stack->stack_queue, msg);
	sys_arch_sem_wait(apimsg->msg.conn->op_completed, 0);
}
#endif


/*---------------------------------------------------------------------------*/

err_t
tcpip_input(struct pbuf *p, struct netif *inp)
{
	struct stack *stack = inp->stack;

	struct tcpip_msg *msg;
	
	//LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip: tcpip_input %p %p\n", (void *)p, (void *) inp));

	msg = memp_malloc(MEMP_TCPIP_MSG);
	if (msg == NULL) {
		pbuf_free(p);  
		return ERR_MEM;  
	}
	
	msg->type = TCPIP_MSG_INPUT;
	msg->msg.inp.p = p;
	msg->msg.inp.netif = inp;
	sys_mbox_post(stack->stack_queue, msg);

	return ERR_OK;
}

/*---------------------------------------------------------------------------*/

void
tcpip_notify(struct netif *netif, u32_t type)
{
	/* Get stack number from interface */
	struct stack *stack = netif->stack;

	struct tcpip_msg *msg;
	sys_sem_t         msg_wait;

	//LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip: tcpip_change %c%c%d type %d (stack=%d)\n", 
	//	netif->name[0],
	//	netif->name[1],
	//	netif->num,
	//	(int)type,
	//	stack));

	msg = memp_malloc(MEMP_TCPIP_MSG);
	if (msg == NULL)
		return;  
	
	msg->type  = TCPIP_MSG_NETIF_NOTIFY;
	msg->msg.netif_notify.netif = netif;
	msg->msg.netif_notify.type  = type;

	msg_wait = sys_sem_new(0);
	msg->msg.netif_notify.sem = &msg_wait;

	sys_mbox_post(stack->stack_queue, msg);

	/* Make this function syncronous. Wait until interface creation */
	sys_sem_wait_timeout(msg_wait, 0); 
	sys_sem_free(msg_wait);
}

/*---------------------------------------------------------------------------*/

struct netif * tcpip_netif_add(
      struct stack *stack, 
      struct netif *netif, 
      void *state,
      err_t (* init)  (struct netif *netif),
      err_t (* input) (struct pbuf *p, struct netif *netif),
      void  (* change)(struct netif *netif, u32_t type))
{
	struct netif     *retval;
	struct tcpip_msg *msg;
	sys_sem_t         msg_wait;

	LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_netif_add: (stack=%d)!\n", stack));

	msg = memp_malloc(MEMP_TCPIP_MSG);
	if (msg == NULL) 
		return NULL;  

	msg->type = TCPIP_MSG_NETIFADD;
	msg->msg.netif.netif = netif;
	msg->msg.netif.state = state;
	msg->msg.netif.init  = init;
	msg->msg.netif.input = input;
	msg->msg.netif.change = change;
	msg->msg.netif.retval = &retval;

	msg_wait = sys_sem_new(0);
	msg->msg.netif.sem = &msg_wait;

	sys_mbox_post(stack->stack_queue, msg);


	LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_netif_add: (stack=%d) wait!\n", stack));
		
	/* Make this function syncronous. Wait until interface creation */
	sys_sem_wait_timeout(msg_wait, 0); 
	sys_sem_free(msg_wait);

	LWIP_DEBUGF(TCPIP_DEBUG, ("tcpip_netif_add: (stack=%d) ok!\n", stack));

	return retval;
}


