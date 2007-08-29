class Handler:
    """ A Stats handler is called to render some stats on the current VSF.

    The stats view is a tree view which gets rendered by calling the relevant stats handler.
    """
    ## This is the name of the stats handler
    name = None

    def __init__(self, case):
        self.case = case

    def display_help(self, result):
        """ This is called when we need to display a helpful message
        about this handler. Usually it is rendered on the right hand
        pane of the tree view.
        """
        result.text(self.__doc__)
        
    def render_tree(self, branch, query):
        """ This generator is called to render the leaf of the tree in
        the stats tree
        """
        raise StopIteration

    def render_pane(self, branch, query, result):
        """ This generator is called to render the leaf of the tree in
        the stats tree
        """
        
