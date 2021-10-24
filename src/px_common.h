#ifndef PX_COMMON__H_
#define PX_COMMON__H_

/*
 *  px_common.h : Common definitions
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

/*
 * The cards are identified by the numbers 1-54 with 53 and 54 being
 * the jokers.
 * To distinguish them from other integers, especially regarding the
 * valid range, they are defined as a separate type.
 */

#include <ctype.h>

typedef char card;

/* CAUTION: Not valid for joker cards, they have no ASCII representation. */
#define CARD2ASCII(c) ((c > 26 ? c - 26 : c) + 0x40)

/* CAUTION: Only valid for alphabetic characters! */
#define ASCII2CARD(c) (toupper(c) - 0x40)

#endif

