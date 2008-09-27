#/usr/bin/env python

from distutils.core import setup
from distutils.extension import Extension

setup( name         = "Volatility",
       version      = "1.3_Linux_rc.1",
       description  = "Volatility -- Volatile memory framwork",
       author       = "AAron Walters",
       author_email = "awalters@volatilesystems.com",  
       url          = "http://www.volatilesystems.com",
       license      = "GPL",
       packages     = ["forensics", "forensics.win32","memory_plugins","memory_objects","memory_objects.Linux","memory_objects.Windows","thirdparty","memory_plugins.Linux","forensics.linux","profiles","profiles.2_6_18-8_1_15_el5"],
       )
