#!/usr/bin/env python3

import os
import argparse
import asyncio
import grp
import logging
import pwd
import signal
import sys
from functools import partial

from .asdnotify import AsyncSystemdNotifier
from . import utils
from . import defaults
from .proactive_fetcher import STSProactiveFetcher
from .responder import STSSocketmapResponder


def parse_args():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-v", "--verbosity",
                        help="logging verbosity",
                        type=utils.check_loglevel,
                        choices=utils.LogLevel,
                        default=utils.LogLevel.info)
    parser.add_argument("-c", "--config",
                        help="config file location",
                        metavar="FILE",
                        default=defaults.CONFIG_LOCATION)
    parser.add_argument("-g", "--group",
                        help="change eGID to this group")
    parser.add_argument("-l", "--logfile",
                        help="log file location",
                        metavar="FILE")
    parser.add_argument("--disable-uvloop",
                        help="do not use uvloop even if it is available",
                        action="store_true")
    parser.add_argument("-p", "--pidfile",
                        help="name of the file to write the current pid to")
    parser.add_argument("-u", "--user",
                        help="change eUID to this user")

    return parser.parse_args()


def exit_handler(exit_event, signum, frame):  # pragma: no cover pylint: disable=unused-argument
    logger = logging.getLogger('MAIN')
    if exit_event.is_set():
        logger.warning("Got second exit signal! Terminating hard.")
        os._exit(1)  # pylint: disable=protected-access
    else:
        logger.warning("Got first exit signal! Terminating gracefully.")
        exit_event.set()


async def heartbeat():
    """ Hacky coroutine which keeps event loop spinning with some interval
    even if no events are coming. This is required to handle Futures and
    Events state change when no events are occurring."""
    while True:
        await asyncio.sleep(.5)


async def amain(cfg):  # pragma: no cover
    logger = logging.getLogger("MAIN")

    proactive_fetch_enabled = cfg['proactive_policy_fetching']['enabled']

    # Create policy cache
    cache = utils.create_cache(cfg["cache"]["type"],
                               cfg["cache"]["options"])
    await cache.setup()

    # Construct request handler
    responder = STSSocketmapResponder(cfg, cache)
    await responder.start()
    logger.info("Server started.")

    # Conditionally construct proactive policy fetcher
    proactive_fetcher = None
    if proactive_fetch_enabled:
        proactive_fetcher = STSProactiveFetcher(cfg, cache)
        await proactive_fetcher.start()
        logger.info("Proactive policy fetcher started.")
    else:
        logger.info("Proactive policy fetching is disabled.")

    exit_event = asyncio.Event()
    beat = asyncio.create_task(heartbeat())
    sig_handler = partial(exit_handler, exit_event)
    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGINT, sig_handler)
    async with AsyncSystemdNotifier() as notifier:
        await notifier.notify(b"READY=1")
        await exit_event.wait()
        logger.debug("Eventloop interrupted. Shutting down server...")
        await notifier.notify(b"STOPPING=1")
    beat.cancel()
    try:
        await beat
    except asyncio.CancelledError:
        pass
    await responder.stop()
    await responder.close()
    if proactive_fetch_enabled:
        await proactive_fetcher.stop()
        await proactive_fetcher.close()
    await cache.teardown()


def main():  # pragma: no cover
    args = parse_args()
    if args.pidfile is not None:
        with open(args.pidfile, 'w', encoding='ascii') as pid_file:
            pid_file.write(str(os.getpid()))
    if args.group is not None:
        try:
            group = grp.getgrnam(args.group)
            os.setegid(group.gr_gid)
        except Exception as exc:
            print("Unable to change eGID to '{}': {}".format(args.group, exc), file=sys.stderr)
            return os.EX_OSERR
    if args.user is not None:
        try:
            passwd = pwd.getpwnam(args.user)
            os.seteuid(passwd.pw_uid)
        except Exception as exc:
            print("Unable to change eUID to '{}': {}".format(args.user, exc), file=sys.stderr)
            return os.EX_OSERR
    with utils.AsyncLoggingHandler(args.logfile) as log_handler:
        logger = utils.setup_logger('MAIN', args.verbosity, log_handler)
        utils.setup_logger('STS', args.verbosity, log_handler)
        utils.setup_logger('PF', args.verbosity, log_handler)
        utils.setup_logger('RES', args.verbosity, log_handler)
        logger.info("MTA-STS daemon starting...")

        # Read config and populate with defaults
        cfg = utils.load_config(args.config)

        # Construct event loop
        logger.info("Starting eventloop...")
        if not args.disable_uvloop:
            if utils.enable_uvloop():
                logger.info("uvloop enabled.")
            else:
                logger.info("uvloop is not available. "
                            "Falling back to built-in event loop.")
        logger.info("Eventloop started.")

        # On Python 3.12+ enable_uvloop() stashed a loop factory (the
        # set_event_loop_policy API is deprecated/removed); pass it to
        # asyncio.run(). On older versions the policy was set directly, so no
        # factory is needed.
        loop_factory = utils.get_uvloop_loop_factory()
        if loop_factory is not None:
            asyncio.run(amain(cfg), loop_factory=loop_factory)
        else:
            asyncio.run(amain(cfg))
        logger.info("Server finished its work.")
    return os.EX_OK
