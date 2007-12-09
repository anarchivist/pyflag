""" This is a parser for the table search widget. The parser
implements a simple language for structured queries depending on the
type of the columns presented.
"""
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.84RC4 Date: Wed May 30 20:48:31 EST 2007$
# ******************************************************
#
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# *
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
# ******************************************************

def eval_expression(elements, name, operator, arg):
#    print "Evaluating %s.%s(%r)" % (name,operator,arg)
    ## Try and find the element with the specified name:
    element = None
    for e in elements:
        if e.name == name:
            element = e
            break
    
    if not element:
        raise RuntimeError("Column %s not known" % name)

    ## Use the element to parse:
    return element.parse(name, operator, arg)

%%
parser SearchParser:
    ignore:    "[ \r\t\n]+"
    
    token END: "$"
    token STR: r'"([^\\"]+|\\.)*"'
    token STR2: r"'([^\\']+|\\.)*'"
    token WORD: '[-:+*/!@$%^&=\<\>.a-zA-Z0-9_]+'
    token LOGICAL_OPERATOR: "(and|or|AND|OR)"

    rule goal<<types>>: clause<<types>>  END {{ return clause }}

    ## A clause is a sequence of expressions seperated by logical
    ## operators. Since our operators are the same as SQL, we just
    ## copy them in.
    rule clause<<types>>: expr<<types>> {{ result = expr }}
                    (
                        LOGICAL_OPERATOR {{ logical_operator = LOGICAL_OPERATOR }}
                        expr<<types>> {{ result = "%s %s %s" % (result, logical_operator, expr) }}
                     )*  {{ return result }}

    ## A term may be encapsulated with " or ' or not. Note that
    ## strings use python to parse out the escape sequences so you can
    ## put \n,\r etc
    rule term: STR {{ return eval(STR) }}
                     | STR2 {{ return eval(STR2) }}
                     | WORD {{ return WORD }}

    ## The basic syntax is: column operator argument . This may also
    ## be encapsulated in ( ) in order to be put into the
    ## clause. Since out operators have the same precendence as SQL we
    ## just need to preserve the ( ).
    rule expr<<types>>: term {{ column = term }}
                     WORD {{ operator = WORD }}
                     term {{ return  eval_expression(types, column,operator,term)}}
                     #Preserve parenthases
                     | '\\(' clause<<types>> '\\)' {{ return "( %s )" % clause }}

%%

def parse_to_sql(text, types):
    P = SearchParser(SearchParserScanner(text))
    try:
        return P.goal(types)
    except runtime.SyntaxError, e:
        raise RuntimeError("\n%s\n%s^\n%s" % (text, '-' * e.pos[2], e.msg))

if __name__=='__main__':
    import pyflag.TableObj as TableObj
    
    types = [ TableObj.TimestampType(name='Timestamp'),
              TableObj.IPType(name='IP Address')]

    test = 'Timestamp < "2006-10-01 \\\"10:10:00\\\"" or (Timestamp before \'2006-11-01 "10:10:00"\' and  "IP Address" netmask "10.10.10.0/24") or "IP Address" = 192.168.1.1'
    print "Will test %s" % test
    print parse_to_sql(test,types)
