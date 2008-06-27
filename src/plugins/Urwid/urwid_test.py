""" This plugin is a proof of concept urwid application. It is
incorporated into PyFlag
"""
import pyflag.Reports as Reports
try:
    import Hexeditor
    import pyflag_display
except ImportError:
    disable = True
    
import sys

class UrwidTest(Reports.report):
    """ A Test of urwid applications """
    parameters = {}
    name = "Urwid Test"
    family = "Test"

    def display(self, query, result):
        ## Create the application
        screen = Hexeditor.Hexeditor(open("/etc/passwd"))
        generator = screen.run()
        generator.next()

        def urwid_cb(query, result):
            result.decoration = "raw"
            if query.has_key("_value"):
                ## Look for key input. Note we are not allowed to send
                ## a screen update in response to key input? This
                ## seems a bit inefficient.
                if query.has_key('input'):
                    ## Schedule it a little
                    generator.send(query.get('_value',''))

                screen.refresh_screen()
                result.content_type = "text/plain"
                result.result = screen.ui.buffer
            else:
                result.content_type = "text/html"
                result.result = "".join(pyflag_display._html_page)                

        result.iframe(callback = urwid_cb)
