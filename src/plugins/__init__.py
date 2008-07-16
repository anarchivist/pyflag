"""Plugins for pyflag go in this directory.

When pyflag is first executed, it searches for plugins in the following places:
      1. In a directory called plugins in the current directory
      2. In the directory marked by the PLUGINS parameter in the configuration file
      3. In the pyflag/plugins module directory if installed in the system

NOTE:

1. Plugins should never execute DB code directly - its ok to use an if
__name__=='__main__' type clause, but otherwise you should just have
class definitions. This is because the module may be loaded several
times and in different points on start up (e.g. before forking - if
you cause db handles to be opened before forking this can cause db
pool corruption).

2. You can define Event handlers to deal with incremental schema
upgrades (add columns, check for tables etc). These checks can be
launched from the startup() method.      
"""
