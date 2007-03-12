import re,sys

class Lexer:
    """ A generic feed lexer """
    ## The following is a description of the states we have and the
    ## way we move through them: format is an array of
    ## [ state_re, re, token/action, next state ]
    tokens = []
    buffer = ''
    error = 0
    state_stack = []
    
    def __init__(self):
        for row in self.tokens:
            row.append(re.compile(row[0]))
            row.append(re.compile(row[1]))

    def next_token(self, end = True):
        ## Now try to match any of the regexes in order:
        for state_re, re_str, token, next, state, regex in self.tokens:
            ## Does the rule apply for us now?
            if state.match(self.state):
                #print "Trying to match %r with %r" % (self.buffer[:10], re_str)
                m = regex.match(self.buffer)
                if m:
                    #print "%s matched %s" % (re_str, m.group(0))
                    ## The match consumes the data off the buffer (the
                    ## handler can put it back if it likes)
                    self.buffer = self.buffer[m.end():]

                    ## Try to iterate over all the callbacks specified:
                    for t in token.split(','):
                        try:
                            #print "Calling %s %r" % (t, m.group(0))
                            cb = getattr(self, t, self.default_handler)
                        except AttributeError:
                            continue

                        ## Is there a callback to handle this action?
                        next_state = cb(t, m)
                        if next_state:
                            next = next_state

                    #print "Going into state %s" % next
                    if next:
                        self.state = next
                        
                    return token

        ## Check that we are making progress - if we are too full, we
        ## assume we are stuck:
        if end and len(self.buffer)>0 or len(self.buffer)>1024:
            print "Lexer Stuck, discarding 1 byte (%r) - state %s" % (self.buffer[:10], self.state)
            self.buffer = self.buffer[1:]
            self.ERROR()
            return "ERROR"

        ## No token were found
        return None
    
    def feed(self, data):
        self.buffer += data

    def empty(self):
        return not len(self.buffer)

    def default_handler(self, token, match):
        pass
        #print "Got %s with %r" % (token,match.group(0))

    def ERROR(self):
        self.error+=1

    def PUSH_STATE(self, token = None, match = None):
        #print "Storing state %s" % self.state
        self.state_stack.append(self.state)

    def POP_STATE(self, token = None, match = None):
        try:
            state = self.state_stack.pop()
            #print "Returned state to %s" % state
            return state
        except IndexError:
            print "Tried to pop the state but failed - possible recursion error"
            return None
