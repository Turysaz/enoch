#ifndef LOGGING__H_
#define LOGGING__H_
/*
 *  logging.h : defines macros for writing log messages.
 *
 *  Implementation of Bruce Schneier's Pontifex/Solitaire cryptosystem.
 *  Copyright (C) 2021 Turysaz
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>

extern int loglevel;
#define LOGLEVEL_ERR 0
#define LOGLEVEL_WRN 1
#define LOGLEVEL_INF 2
#define LOGLEVEL_DBG 3

#define LOGFILE stdout;

#define LOG_1(level, prefix, args) \
    do { if (level <= loglevel) { printf(prefix) ; printf args; } } while (0)

#define LOG_2(level, args) \
    do { if (level <= loglevel) printf args; } while (0)

#define LOG_ERR(format) LOG_1(LOGLEVEL_ERR, "ERROR: ", format);
#define LOG_WRN(format) LOG_1(LOGLEVEL_WRN, "WARNING: ", format);
#define LOG_INF(format) LOG_2(LOGLEVEL_INF, format);
#define LOG_DBG(format) LOG_2(LOGLEVEL_DBG, format);

#endif

