""" This is a module which exports a set of plotters based on
matplotlib. Yoy will need to have matplotlib installed using something
like:

apt-get install python-matplotlib

"""
import pyflag.DB as DB
import pyflag.Graph as Graph

try:
    import matplotlib
    matplotlib.use('Agg')
    
    from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
    from matplotlib.figure import Figure
    
    import numpy as np

    import matplotlib.image as image
    import matplotlib.figure as figure
    import StringIO
    from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
    import tempfile
except ImportError:
    active = False

class LinePlot(Graph.GenericGraph):
    name = 'Line Plot'

    def form(self, query, result):
        pass

    def plot(self, gen, query, result):
        fig = figure.Figure()
        ax = fig.add_subplot(111)
        x=[]
        y=[]
        for a,b in gen:
            x.append(a)
            y.append(b)
        
        ax.plot(x,y , '.')
        ax.grid()

        ## Make a temporary file name:
        fd = tempfile.TemporaryFile()
        canvas=FigureCanvas(fig)
        canvas.print_figure(fd) 
        fd.seek(0)

        result.generator.content_type = "image/png"
        result.generator.generator = [ fd.read(), ]
