/* This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                          *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:         *
 *                          *
 * Free Software Foundation      Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330   Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org         *
 *                                                                  *
 *  Copyright  2004-2005  Neil Williams  <linux@codehelp.co.uk>
 *                                                                  *
 ******************************************************************/
/** This set of macros allows for simple accessors for enums by name.

 This makes enums much simpler to use as we can emit more useful
 debugging messages, and even read and write enum values from/to disk
 etc.

 To use, include this file first. Define a macro to contain all the enum elements in it:

#define ENUM_EVENT_TYPE(_)			\
  _(EVENT_CONNECT) _(EVENT_RESET) _(EVENT_PROCESS_NEW) _(EVENT_PROCESS_END)

and then define the enum:
DEFINE_ENUM(Event_Type , ENUM_EVENT_TYPE);

When you need to print the names of the enum elements define the accessor function as:
AS_STRING_FUNC(Event_Type , ENUM_EVENT_TYPE);

The function will be called const char *Event_Type_asString(enum Event_Type id);

Similarly for
FROM_STRING_FUNC(Event_Type, ENUM_EVENT_TYPE);

will produce enum Event_Type Event_Type_fromString(char *string);

*/
#ifndef __ENUM_H
#define __ENUM_H

#define ENUM_BODY(name)           \
    name,
#define AS_STRING_CASE(name)      \
    case name: return #name;
#define FROM_STRING_CASE(name)    \
    if (strcmp(str, #name) == 0) {       \
        return name;                     \
    }
#define DEFINE_ENUM(name, list)          \
    enum name {                       \
      list(ENUM_BODY) LAST_ITEM_##name \
    };
#define AS_STRING_DEC(name, list)        \
    const char* name##_asString(enum name n);
#define FROM_STRING_DEC(name, list)      \
    name name##_fromString(const char* str);


#ifdef __DEBUG__
#define FROM_STRING_FUNC(name, list)     \
    enum name name##_fromString(const char* str) {   \
        list(FROM_STRING_CASE)           \
        return 0;                        \
    }
#define AS_STRING_FUNC(name, list)       \
    const char* name##_asString(enum name n) {       \
        switch (n) {                     \
            list(AS_STRING_CASE)         \
            default: return "";          \
        }                                \
    }
#else 
#define FROM_STRING_FUNC(name, list)     \
  enum name name##_fromString(const char* str) { return 0;}

#define AS_STRING_FUNC(name, list)       \
  const char* name##_asString(enum name n) { return ""};
#endif

#endif
