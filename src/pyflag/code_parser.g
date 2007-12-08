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
    return element.parse(name, operator, arg, context='code')

def logical_operator_parse(left, operator, right):
    if operator=="and":
        return lambda row: left(row) and right(row)
    elif operator=="or":
        return lambda row: left(row) or right(row)

    raise RuntimeError("operator %s not supported" % operator)

%%
parser CodeParser:
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
                        expr<<types>> {{ result = logical_operator_parse(result, logical_operator, expr) }}
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
                     | '\\(' clause<<types>> '\\)' {{ return  clause }}

%%

def parse_eval(text, types):
    """ This return a parse tree from the expression in text using the
    table objects in types.

    A parse tree is essentially a function which may be called with:
    function(row)

    where row is a dict containing all the column in the row. The
    function returns True if the filter expression applies to the row
    or False otherwise.

    Note that once the filter is parsed there is no need to re-parse
    it for each row, just reuse the function over and over. This is
    very fast.
    """
    P = CodeParser(CodeParserScanner(text))
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
    print parse_eval(test,types)
