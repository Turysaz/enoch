#ifndef LOGGING__H_
#define LOGGING__H_

/*
 *  Implementation of Bruce Schneier's Pontifex/Solitaire cryptosystem.
 *  Copyright (C) 2021 Turysaz
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Library General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Library General Public License for more details.
 *
 *  You should have received a copy of the GNU Library General Public
 *  License along with this library; if not, write to the
 *  Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 *  Boston, MA  02110-1301, USA.
 */

#include <stdio.h>

extern int loglevel;
#define LOGLEVEL_ERR 0
#define LOGLEVEL_WRN 1
#define LOGLEVEL_INF 2
#define LOGLEVEL_DBG 3

#define LOGFILE stdout;

/* For variadic macros, especially for the '##' symbol, see:
 * https://gcc.gnu.org/onlinedocs/cpp/Variadic-Macros.html
 * TODO: Variadic macros are a C99 feature and should be
 *       replaced by some ANSI-C mechanism.
 */
#define LOG(level, format, ...) if (level <= loglevel) printf(format, ##__VA_ARGS__ );
#define LOG_ERR(format, ...) LOG(LOGLEVEL_ERR, "ERROR: " format, ##__VA_ARGS__ );
#define LOG_WRN(format, ...) LOG(LOGLEVEL_WRN, "WARNING: " format, ##__VA_ARGS__ );
#define LOG_INF(format, ...) LOG(LOGLEVEL_INF, format, ##__VA_ARGS__ );
#define LOG_DBG(format, ...) LOG(LOGLEVEL_DBG, format, ##__VA_ARGS__ );

#endif

