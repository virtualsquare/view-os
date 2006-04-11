/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2003-2004, Valient Gough
 * Modified 2006 Paolo Beverini
 *
 * This library is free software; you can distribute it and/or modify it under
 * the terms of the GNU General Public License (GPL), as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GPL in the file COPYING for more
 * details.
 *
 */

#include "encfs.h"
#include "config.h"
#include "autosprintf.h"

#include <iostream>
#include <string>
#include <sstream>

#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <errno.h>

#include <getopt.h>

#include <rlog/rlog.h>
#include <rlog/Error.h>
#include <rlog/RLogChannel.h>
#include <rlog/SyslogNode.h>
#include <rlog/StdioNode.h>

#include "Config.h"
#include "Interface.h"
#include "MemoryPool.h"
#include "FileUtils.h"
#include "DirNode.h"

#ifdef HAVE_SSL
#define NO_DES
#include <openssl/ssl.h>
#include <openssl/rand.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#endif

#include <locale.h>

#include "i18n.h"

#ifndef MAX
inline static int MAX(int a, int b)
{
    return (a > b) ? a : b;
}
#endif

using namespace std;
using namespace rlog;
using namespace rel;
using namespace gnu;

const int MaxFuseArgs = 32;

struct EncFS_Args
{
    string mountPoint; // where to make filesystem visible
    bool isDaemon; // true == spawn in background, log to syslog
    bool isThreaded; // true == threaded
    bool isVerbose; // false == only enable warning/error messages
    int idleTimeout; // 0 == idle time in minutes to trigger unmount
    const char *fuseArgv[MaxFuseArgs];
    int fuseArgc;

    EncFS_Opts opts;

    // for debugging
    // In case someone sends me a log dump, I want to know how what options are
    // in effect.  Not internationalized, since it is something that is mostly
    // useful for me!
    string toString()
    {
        ostringstream ss;
        ss << (isDaemon ? "(daemon) " : "(fg) ");
        ss << (isThreaded ? "(threaded) " : "(UP) ");
        if(idleTimeout > 0)
            ss << "(timeout " << idleTimeout << ") ";
        if(opts.checkKey) ss << "(keyCheck) ";
        if(opts.forceDecode) ss << "(forceDecode) ";
        if(opts.ownerCreate) ss << "(ownerCreate) ";
        if(opts.useStdin) ss << "(useStdin) ";
        for(int i=0; i<fuseArgc; ++i)
            ss << fuseArgv[i] << ' ';

        return ss.str();
    }
};

struct EncfsFSContext
{
    EncFS_Args *args;

    // for idle monitor
    bool running;
    pthread_t monitorThread;
    pthread_cond_t wakeupCond;
    pthread_mutex_t wakeupMutex;

    DirNode *FSRoot;
// if gPublicFilesystem is true, then try and make the filesystem behave like a
// normal multi-user filesystem (nodes are owned by the uid of the caller, etc)
    bool gPublicFilesystem;
    int oldStderr;
};


//needed to comunicate the context from main to encfs_init
EncfsFSContext *glctx=NULL;


// Maximum number of arguments that we're going to pass on to fuse.  Doesn't
// affect how many arguments we can handle, just how many we can pass on..

static
void usage(const char *name)
{
    // xgroup(usage)
    cerr << autosprintf( _("Build: encfs version %s"), VERSION ) 
	<< "\n\n"
	// xgroup(usage)
	<< autosprintf(_("Usage: %s [options] rootDir mountPoint [-- [FUSE Mount Options]]"), name) << "\n\n"
	// xgroup(usage)
	<< _("Common Options:\n"
	"  -H\t\t\t"       "show optional FUSE Mount Options\n"
	"  -s\t\t\t"       "disable multithreaded operation\n"
	"  -f\t\t\t"       "run in foreground (don't spawn daemon).\n"
	             "\t\t\tError messages will be sent to stderr\n"
		     "\t\t\tinstead of syslog.\n")

	// xgroup(usage)
	<< _("  -v, --verbose\t\t"   "verbose: output encfs debug messages\n"
	"  -i, --idle=MINUTES\t""Auto unmount after period of inactivity\n"
	"  --anykey\t\t"        "Do not verify correct key is being used\n"
	"  --forcedecode\t\t"   "decode data even if an error is detected\n"
	                  "\t\t\t(for filesystems using MAC block headers)\n")
	<< _("  --public\t\t"   "act as a typical multi-user filesystem\n"
	                  "\t\t\t(encfs must be run as root)\n")

	// xgroup(usage)
	<< _("  --extpass=program\tUse external program for password prompt\n"
	"\n"
	"Example, to mount at ~/crypt with raw storage in ~/.crypt :\n"
	"    encfs ~/.crypt ~/crypt\n"
	"\n")
	// xgroup(usage)
	<< _("For more information, see the man page encfs(1)") << "\n"
	<< endl;
}

static
void FuseUsage()
{
    // xgroup(usage)
    cerr << _("encfs [options] rootDir mountPoint -- [FUSE Mount Options]\n"
	    "valid FUSE Mount Options follow:\n") << endl;

    int argc = 2;
    const char *argv[] = {"...", "-h"};
    fuse_main( argc, const_cast<char**>(argv), (fuse_operations*)NULL);
}

#define PUSHARG(ARG) \
rAssert(out->fuseArgc < MaxFuseArgs); \
out->fuseArgv[out->fuseArgc++] = ARG

static
string slashTerminate( const string &src )
{
    string result = src;
    if( result[ result.length()-1 ] != '/' )
	result.append( "/" );
    return result;
}

static 
bool processArgs(int argc, char *argv[], EncFS_Args *out)
{
   optind=0;
    // set defaults
    out->isDaemon = true;
#if defined(HAVE_ATOMIC_GCC) || defined(HAVE_ATOMIC_GCC_PRIVATE)
    out->isThreaded = true;
#else
    // no atomic update methods -- safest to stick to single-threaded mode..
    out->isThreaded = false;
#endif
    out->isVerbose = false;
    out->idleTimeout = 0;
    out->fuseArgc = 0;
    out->opts.idleTracking = false;
    out->opts.checkKey = true;
    out->opts.forceDecode = false;
    out->opts.ownerCreate = false;
    out->opts.useStdin = false;
    
    bool useDefaultFlags = true;

    // pass executable name through
    out->fuseArgv[0] = lastPathElement(argv[0]);
    ++out->fuseArgc;

    // leave a space for mount point, as FUSE expects the mount point before
    // any flags
    out->fuseArgv[1] = NULL;
    ++out->fuseArgc;
   
    // TODO: can flags be internationalized?
    static struct option long_options[] = {
	{"fuse-debug", 0, 0, 'd'}, // Fuse debug mode
	{"forcedecode", 0, 0, 'D'}, // force decode
	// {"foreground", 0, 0, 'f'}, // foreground mode (no daemon)
	{"fuse-help", 0, 0, 'H'}, // fuse_mount usage
	{"idle", 1, 0, 'i'}, // idle timeout
	{"anykey", 0, 0, 'k'}, // skip key checks
	{"no-default-flags", 0, 0, 'N'}, // don't use default fuse flags
	{"public", 0, 0, 'P'}, // public mode
	{"extpass", 1, 0, 'p'}, // external password program
	// {"single-thread", 0, 0, 's'}, // single-threaded mode
	{"stdinpass", 1, 0, 'S'}, // read password from stdin
	{"verbose", 0, 0, 'v'}, // verbose mode
	{"version", 0, 0, 'V'}, //version
	{0,0,0,0}
    };

    while (1)
    {
	int option_index = 0;

	// 's' : single-threaded mode
	// 'f' : foreground mode
	// 'v' : verbose mode (same as --verbose)
	// 'd' : fuse debug mode (same as --fusedebug)
	// 'i' : idle-timeout, takes argument
	// 'S' : password from stdin
	int res = getopt_long( argc, argv, "HsSfvdi:",
		long_options, &option_index);

	if(res == -1)
	    break;

	switch( res )
	{
	case 's':
	    out->isThreaded = false;
	    break;
	case 'S':
	    out->opts.useStdin = true;
	    break;
	case 'f':
	    out->isDaemon = false;
	    // this option was added in fuse 2.x
	    PUSHARG("-f");
	    break;
	case 'v':
	    out->isVerbose = true;
	    break;
	case 'd':
	    PUSHARG("-d");
	    break;
	case 'i':
#if FUSE_MAJOR_VERSION == 2 && FUSE_MINOR_VERSION == 2
	    cerr << "Sorry, idle monitoring not enabled. "
		"FUSE 2.3 or newer required.\n" 
		<< endl;
#else
	    out->idleTimeout = strtol( optarg, (char**)NULL, 10);
	    out->opts.idleTracking = true;
#endif
	    break;
	case 'k':
	    out->opts.checkKey = false;
	    break;
	case 'D':
	    out->opts.forceDecode = true;
	    break;
	case 'N':
	    useDefaultFlags = false;
	    break;
	case 'p':
	    out->opts.passwordProgram.assign( optarg );
	    break;
	case 'P':
	    if(geteuid() != 0)
		rWarning(_("option '--public' ignored for non-root user"));
	    else
	    {
		out->opts.ownerCreate = true;
		// add 'allow_other' option
		// add 'default_permissions' option (default)
		PUSHARG("-o");
		PUSHARG("allow_other");
	    }
	    break;
	case 'V':
	    // xgroup(usage)
	    cerr << autosprintf(_("encfs version %s"), VERSION) << endl;
	    exit(EXIT_SUCCESS);
	    break;
	case 'H':
	    FuseUsage();
	    exit(EXIT_SUCCESS);
	    break;
	case '?':
	    // invalid options..
	    break;
	case ':':
	    // missing parameter for option..
	    break;
	default:
	    rWarning(_("getopt error: %i"), res);
	    break;
	}
    }

    if(!out->isThreaded)
	PUSHARG("-s");

    if(useDefaultFlags)
    {
	PUSHARG("-o");
	PUSHARG("use_ino");
	PUSHARG("-o");
	PUSHARG("default_permissions");
    }
	    
    // we should have at least 2 arguments left over - the source directory and
    // the mount point.
    if(optind+2 <= argc)
    {
	out->opts.rootDir = slashTerminate( argv[optind++] );
	out->mountPoint = argv[optind++];
    } else
    {
	// no mount point specified
	rWarning(_("Missing one or more arguments, aborting."));
	return false;
    }

    // If there are still extra unparsed arguments, pass them onto FUSE..
    if(optind < argc)
    {
	rAssert(out->fuseArgc < MaxFuseArgs);

	while(optind < argc)
	{
	    rAssert(out->fuseArgc < MaxFuseArgs);
	    out->fuseArgv[out->fuseArgc++] = argv[optind];
	    ++optind;
	}
    }

    // sanity check
    if(out->isDaemon && 
	    (!isAbsolutePath( out->mountPoint.c_str() ) ||
	    !isAbsolutePath( out->opts.rootDir.c_str() ) ) 
      )
    {
	cerr << 
	    // xgroup(usage)
	    _("When specifying daemon mode, you must use absolute paths "
		    "(beginning with '/')")
	    << endl;
	return false;
    }

    // the raw directory may not be a subdirectory of the mount point.
    {
	string testMountPoint = slashTerminate( out->mountPoint );
	string testRootDir = 
	    out->opts.rootDir.substr(0, testMountPoint.length());

	if( testMountPoint == testRootDir )
	{
	    cerr << 
		// xgroup(usage)
		_("The raw directory may not be a subdirectory of the "
		  "mount point.") << endl;
	    return false;
	}
    }

    // check that the directories exist, or that we can create them..
    if(!isDirectory( out->opts.rootDir.c_str() ) && 
	    !userAllowMkdir( out->opts.rootDir.c_str() ,0700))
    {
	rWarning(_("Unable to locate root directory, aborting."));
	return false;
    }
    if(!isDirectory( out->mountPoint.c_str() ) && 
	    !userAllowMkdir( out->mountPoint.c_str(),0700))
    {
	rWarning(_("Unable to locate mount point, aborting."));
	return false;
    }

    // fill in mount path for fuse
    out->fuseArgv[1] = out->mountPoint.c_str();

    return true;
}

/*
    I think I nabbed this stuff from a test program from the OpenSSL
    distribution..
*/
#ifdef HAVE_SSL
unsigned long pthreads_thread_id()
{
    return (unsigned long)pthread_self();
}

static pthread_mutex_t *crypto_locks = NULL;
void pthreads_locking_callback( int mode, int n,
	const char *caller_file, int caller_line )
{
    (void)caller_file;
    (void)caller_line;

    if(!crypto_locks)
    {
	rDebug("Allocating %i locks for OpenSSL", CRYPTO_num_locks() );
	crypto_locks = new pthread_mutex_t[ CRYPTO_num_locks() ];
	for(int i=0; i<CRYPTO_num_locks(); ++i)
	    pthread_mutex_init( crypto_locks+i, 0 );
    }

    if(mode & CRYPTO_LOCK)
    {
	pthread_mutex_lock( crypto_locks + n );
    } else
    {
	pthread_mutex_unlock( crypto_locks + n );
    }
}

void pthreads_locking_cleanup()
{
    if(crypto_locks)
    {
	for(int i=0; i<CRYPTO_num_locks(); ++i)
	    pthread_mutex_destroy( crypto_locks+i );
	delete[] crypto_locks;
	crypto_locks = NULL;
    }
}
#endif

/*
    Idle monitoring thread.  This is only used when idle monitoring is enabled.
    It will cause the filesystem to be automatically unmounted (causing us to
    commit suicide) if the filesystem stays idle too long.  Idle time is only
    checked if there are no open files, as I don't want to risk problems by
    having the filesystem unmounted from underneath open files!
*/
const int MinActivityCheckInterval = 10;

static
void * idleMonitor(void *_arg)
{
    EncfsFSContext *ctx = (EncfsFSContext*)_arg;
    EncFS_Args *arg = ctx->args;

    int timeoutSeconds = 60 * arg->idleTimeout;

    pthread_mutex_lock( &ctx->wakeupMutex );
    
    while(ctx->running)
    {
	int nextCheck = MinActivityCheckInterval;

	int idleSeconds = ctx->FSRoot->idleSeconds();
	if(idleSeconds >= timeoutSeconds)
	{
	    if( !ctx->FSRoot->hasOpenFiles() )
	    {
		// Time to unmount!
		// xgroup(diag)
		rWarning(_("Unmounting filesystem %s due to inactivity"),
			arg->mountPoint.c_str());
		fuse_unmount( arg->mountPoint.c_str() );
		// wait for main thread to wake us up
		pthread_cond_wait( &ctx->wakeupCond, &ctx->wakeupMutex );
		break;
	    } else
	    {
		rDebug("open files: \n%s", ctx->FSRoot->openFileList().c_str());
	    }
	} else
	{
	    // don't need to check again until it could possibly timeout
	    nextCheck = MAX(timeoutSeconds - idleSeconds,
		            MinActivityCheckInterval);
	    rDebug("checking idle time again in %i seconds", nextCheck);
	}

	struct timeval currentTime;
	gettimeofday( &currentTime, 0 );
	struct timespec wakeupTime;
	wakeupTime.tv_sec = currentTime.tv_sec + nextCheck;
	wakeupTime.tv_nsec = currentTime.tv_usec * 1000;
	pthread_cond_timedwait( &ctx->wakeupCond, 
		&ctx->wakeupMutex, &wakeupTime );
    }
    
    pthread_mutex_unlock( &ctx->wakeupMutex );

    rDebug("Idle monitoring thread exiting");

    return 0;
}

void *encfs_init()
{
    EncfsFSContext *ctx;

    fuse_context *mycontext=fuse_get_context();
    ctx=(EncfsFSContext *) mycontext->private_data;
    if (ctx==NULL) ctx=glctx;

    // if an idle timeout is specified, then setup a thread to monitor the
    // filesystem.
    if(ctx->args->idleTimeout > 0)
    {
	rDebug("starting idle monitoring thread");
	ctx->running = true;
	pthread_cond_init( &ctx->wakeupCond, 0 );
	pthread_mutex_init( &ctx->wakeupMutex, 0 );

	int res = pthread_create( &ctx->monitorThread, 0, idleMonitor, 
		(void*)ctx );
	if(res != 0)
	{
	    rError("error starting idle monitor thread, "
		    "res = %i, errno = %i", res, errno);
	}
    }

    if(ctx->oldStderr >= 0)
    {
	close(ctx->oldStderr);
	ctx->oldStderr = -1;
    }

    return (void*)ctx;
}
 
void encfs_destroy( void *_ctx )
{
    EncfsFSContext *ctx = (EncfsFSContext*)_ctx;
    if(ctx->args->idleTimeout > 0)
    {
	ctx->running = false;

	// wake up the thread if it is waiting..
	rDebug("waking up monitoring thread");
	pthread_mutex_lock( &ctx->wakeupMutex );
	pthread_cond_signal( &ctx->wakeupCond );
	pthread_mutex_unlock( &ctx->wakeupMutex );
	rDebug("joining with idle monitoring thread");
	pthread_join( ctx->monitorThread , 0 );
	rDebug("join done");
    }
}

int main(int argc, char *argv[])
{
    // initialize the logging library
    RLogInit( argc, argv );

   bool publicFs;
   DirNode *fsR;

#ifdef LOCALEDIR
    setlocale( LC_ALL, "" );
    bindtextdomain( PACKAGE, LOCALEDIR );
    textdomain( PACKAGE );
#endif

#ifdef HAVE_SSL
    // initialize the SSL library
    SSL_load_error_strings();
    SSL_library_init();

    unsigned int randSeed = 0;
    RAND_bytes( (unsigned char*)&randSeed, sizeof(randSeed) );
    srand( randSeed );

#ifndef OPENSSL_NO_ENGINE
    // initialize hardware crypto engine support
    ENGINE_load_builtin_engines();
    ENGINE_register_all_ciphers();
    ENGINE_register_all_digests();
    ENGINE_register_all_RAND();
#endif // NO_ENGINE
#endif

    // log to stderr by default..
    StdioNode *slog = new StdioNode( STDERR_FILENO );
    SyslogNode *logNode = NULL;

    // show error and warning output
    slog->subscribeTo( GetGlobalChannel("error") );
    slog->subscribeTo( GetGlobalChannel("warning") );

    // anything that comes from the user should be considered tainted until
    // we've processed it and only allowed through what we support.
    EncFS_Args *encfsArgs = new EncFS_Args;
    for(int i=0; i<MaxFuseArgs; ++i)
	encfsArgs->fuseArgv[i] = NULL; // libfuse expects null args..

    if(argc == 1 || !processArgs(argc, argv, encfsArgs))
    {
	usage(argv[0]);
	return EXIT_FAILURE;
    }

    if(encfsArgs->isVerbose)
    {
	// subscribe to more logging channels..
	slog->subscribeTo( GetGlobalChannel("info") );
	slog->subscribeTo( GetGlobalChannel("debug") );
    }
  
#ifdef HAVE_SSL
    if(encfsArgs->isThreaded)
    {
	// provide locking functions to OpenSSL since we'll be running with
	// threads accessing openssl in parallel.
	CRYPTO_set_id_callback( pthreads_thread_id );
	CRYPTO_set_locking_callback( pthreads_locking_callback );
    }
#endif

    rDebug("Root directory: %s", encfsArgs->opts.rootDir.c_str());
    rDebug("Fuse arguments: %s", encfsArgs->toString().c_str());
	
    fuse_operations encfs_oper;
    // in case this code is compiled against a newer FUSE library and new
    // members have been added to fuse_operations, make sure they get set to
    // 0..
    memset(&encfs_oper, 0, sizeof(fuse_operations));

    encfs_oper.getattr = encfs_getattr;
    encfs_oper.readlink = encfs_readlink;
    encfs_oper.getdir = encfs_getdir;
    encfs_oper.mknod = encfs_mknod;
    encfs_oper.mkdir = encfs_mkdir;
    encfs_oper.unlink = encfs_unlink;
    encfs_oper.rmdir = encfs_rmdir;
    encfs_oper.symlink = encfs_symlink;
    encfs_oper.rename = encfs_rename;
    encfs_oper.link = encfs_link;
    encfs_oper.chmod = encfs_chmod;
    encfs_oper.chown = encfs_chown;
    encfs_oper.truncate = encfs_truncate;
    encfs_oper.utime = encfs_utime;
    encfs_oper.open = encfs_open;
    encfs_oper.read = encfs_read;
    encfs_oper.write = encfs_write;
    encfs_oper.statfs = encfs_statfs;
    //encfs_oper.flush = encfs_flush;
    encfs_oper.release = encfs_release;
    encfs_oper.fsync = encfs_fsync;
#ifdef HAVE_XATTR
    encfs_oper.setxattr = encfs_setxattr;
    encfs_oper.getxattr = encfs_getxattr;
    encfs_oper.listxattr = encfs_listxattr;
    encfs_oper.removexattr = encfs_removexattr;
#endif // HAVE_XATTR
#if FUSE_MINOR_VERSION >= 3 || FUSE_MAJOR_VERSION > 2
    // .init and .destroy added in fuse 2.3
    // encfs requires fuse 2.2 at a minimum..
    encfs_oper.init = encfs_init;
    encfs_oper.destroy = encfs_destroy;
#endif

    publicFs = encfsArgs->opts.ownerCreate;
    RootPtr rootInfo = initFS( &encfsArgs->opts );

    int returnCode = EXIT_FAILURE;
    EncfsFSContext *ctx = new EncfsFSContext;
    ctx->oldStderr = STDERR_FILENO;

    //there is not other way to give the context to encfs_init
    glctx=ctx;

    if( !rootInfo.isNull() )
    {
	// set the globally visible root directory node
	fsR = rootInfo->root.get();

	    
	if(encfsArgs->isThreaded == false && encfsArgs->idleTimeout > 0)
	{
	    // xgroup(usage)
	    cerr << _("Note: requested single-threaded mode, but an idle\n"
		    "timeout was specified.  The filesystem will operate\n"
		    "single-threaded, but threads will still be used to\n"
		    "implement idle checking.") << endl;
	}

	// reset umask now, since we don't want it to interfere with the
	// pass-thru calls..
	umask( 0 );

	if(encfsArgs->isDaemon)
	{
	    // switch to logging just warning and error messages via syslog
	    logNode = new SyslogNode( "encfs" );
	    logNode->subscribeTo( GetGlobalChannel("warning") );
	    logNode->subscribeTo( GetGlobalChannel("error") );

	    // disable stderr reporting..
	    delete slog;
	    slog = NULL;

	    // keep around a pointer just in case we end up needing it to
	    // report a fatal condition later (fuse_main exits unexpectedly)...
	    ctx->oldStderr = dup( STDERR_FILENO );
	}

	try
	{
	    time_t startTime, endTime;
	   
	    // FIXME: workaround for fuse_main returning an error on normal
	    // exit.  Only print information if fuse_main returned
	    // immediately..
	    time( &startTime );

        ctx->args = encfsArgs;
        ctx->gPublicFilesystem=publicFs;
        ctx->FSRoot= fsR;
        struct fuse_context *mycontext = fuse_get_context();
        mycontext->private_data=(void*) ctx;

	    // fuse_main returns an error code in newer versions of fuse..
	    int res = fuse_main( encfsArgs->fuseArgc, 
		    const_cast<char**>(encfsArgs->fuseArgv), 
		    &encfs_oper);
	    
	    time( &endTime );

	    if(res == 0)
		returnCode = EXIT_SUCCESS;

	    if(res != 0 && encfsArgs->isDaemon && (ctx->oldStderr >= 0)
		    && (endTime - startTime <= 1) )
	    {
		// the users will not have seen any message from fuse, so say a
		// few words in libfuse's memory..
		FILE *out = fdopen( ctx->oldStderr, "a" );
		// xgroup(usage)
		fprintf(out, _("fuse failed.  Common problems:\n"
			" - fuse kernel module not installed (modprobe fuse)\n"
			" - invalid options -- see usage message\n"));
		fclose(out);
	    }
	} catch(std::exception &ex)
	{
	    rError(_("Internal error: Caught exception from main loop: %s"), 
		    ex.what());
	} catch(...)
	{
	    rError(_("Internal error: Caught unexpected exception"));
	}
    }

    // cleanup so that we can check for leaked resources..
    rootInfo.reset();
    ctx->FSRoot = NULL;

    MemoryPool::destroyAll();
#ifdef HAVE_SSL
    if(encfsArgs->isThreaded)
	pthreads_locking_cleanup();
#endif
    delete logNode;
    delete encfsArgs;

    return returnCode;
}
