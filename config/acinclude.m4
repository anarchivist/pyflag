AC_DEFUN([AC_PYTHON_DEVEL],[
	#
	# should allow for checking of python version here...
	#
	AC_REQUIRE([AM_PATH_PYTHON])

	# Check for Python include path
	AC_MSG_CHECKING([for python include path])
	PYTHON_INCLUDE_DIR=`$PYTHON -c "import distutils.sysconfig;print distutils.sysconfig.get_python_inc() "
	AC_MSG_RESULT($PYTHON_INCLUDE_DIR)`
	AC_SUBST([PYTHON_CPPFLAGS],[-I$PYTHON_INCLUDE_DIR])

	if [ test ! -r $PYTHON_INCLUDE_DIR/Python.h ]; then AC_MSG_ERROR(failed to find include file $PYTHON_INCLUDE_DIR/Python.h maybe you need to install python-dev?); fi

	# Check for Python library path
	AC_MSG_CHECKING([for python library path])
	PYTHON_EXTRA_LIBS=`$PYTHON -c "import distutils.sysconfig;print distutils.sysconfig.get_python_lib() "
	AC_MSG_RESULT($PYTHON_LDFLAGS)`
	AC_SUBST([PYTHON_LDFLAGS],["-L$python_path -lpython$PYTHON_VERSION"])

	#
	python_site=`echo $python_path | sed "s/config/site-packages/"`
	AC_SUBST([PYTHON_SITE_PKG],[$python_site])
	#
	# libraries which must be linked in when embedding
	#
	AC_MSG_CHECKING(python extra libraries)
	PYTHON_EXTRA_LIBS=`$PYTHON -c "import distutils.sysconfig;conf = distutils.sysconfig.get_config_var;print conf('LOCALMODLIBS')+' '+conf('LIBS')"
	AC_MSG_RESULT($PYTHON_EXTRA_LIBS)`
	AC_SUBST(PYTHON_EXTRA_LIBS)
])

AC_DEFUN([AC_PYTHON_XCOMPILE_WINDOWS], [
	## This is used to specify the cross compiled windows binaries
	AC_MSG_CHECKING([Setting Windows Python Paths])
	PYTHON_INCLUDE_DIR=$1/include
	AC_SUBST([PYTHON_CPPFLAGS], [-I$PYTHON_INCLUDE_DIR])
	if [ test ! -r $PYTHON_INCLUDE_DIR/Python.h ]; then AC_MSG_ERROR(failed to find include file $PYTHON_INCLUDE_DIR/Python.h maybe you need to install python-dev?); fi
	
	## Set library paths
	AC_SUBST([PYTHON_LDFLAGS],["-shared"])	
	AC_SUBST([PYTHON_EXTRA_LIBS], [" -L$1/libs/ -lpython25 -lwsock32"])
	AC_SUBST([PYTHON_SITE_PKG], [$1])
	AC_SUBST([PYTHON_EXTENSION], [".pyd"])
])

AC_DEFUN([AC_PYTHON_MODULE],[
	AC_MSG_CHECKING(python module: $1)
	$PYTHON -c "import $1" 2>/dev/null
	if test $? -eq 0;
	then
		AC_MSG_RESULT(yes)
		eval AS_TR_CPP(HAVE_PYMOD_$1)=yes
	else
		AC_MSG_RESULT(no)
		eval AS_TR_CPP(HAVE_PYMOD_$1)=no
		#
		if test "REQUIRED" == "$2"
		then
			if test -n "$3"
			then	
				AC_MSG_ERROR($3)			
			else
				AC_MSG_ERROR(failed to find required python module $1)
			fi
			exit 1
		else
			AC_MSG_WARN($3)
		fi
	fi
])

# AZ_PYTHON_WITH( [path] )
# -----------------------------------------------------------------
# Handles the various --with-python commands.
# Input:
#   $1 is the optional search path for the python executable if needed
# Ouput:
#   PYTHON_USE (AM_CONDITIONAL) is true if python executable found
#   and --with-python was requested; otherwise false.
#   $PYTHON contains the full executable path to python if PYTHON_USE
#   is true.
#
# Example:
#   AZ_PYTHON_WITH( )
#   or
#   AZ_PYTHON_WITH("/usr/bin")

AC_DEFUN([AZ_PYTHON_WITH],
[
    AC_ARG_VAR([PYTHON],[Python Executable Path])

    # unless PYTHON was supplied to us (as a precious variable),
    # see if --with-python[=PythonExecutablePath], --with-python,
    # --without-python or --with-python=no was given.
    if test -z "$PYTHON"
    then
        AC_MSG_CHECKING(for --with-python)
        AC_ARG_WITH(
            python,
            AC_HELP_STRING([--with-python@<:@=PYTHON@:>@],
                [absolute path name of Python executable]
            ),
            [
                if test "$withval" = "yes"
                then
                    # "yes" was specified, but we don't have a path
                    # for the executable.
                    # So, let's searth the PATH Environment Variable.
                    AC_MSG_RESULT(yes)
                    AC_PATH_PROG(
                        [PYTHON],
                        python,
                        [],
                        $1
                    )
                    if test -z "$PYTHON"
                    then
                        AC_MSG_ERROR(no path to python found)
                    fi
                    az_python_use=true
                    AM_CONDITIONAL(PYTHON_USE, test x"$az_python_use" = x"true")
                    AZ_PYTHON_PREFIX( )
                elif test "$withval" = "no"
                then
                    AC_MSG_RESULT(no)
                    az_python_use=false
                    AM_CONDITIONAL(PYTHON_USE, test x"$az_python_use" = x"true")
                else
                    # $withval must be the executable path then.
                    AC_SUBST([PYTHON], ["${withval}"])
                    AC_MSG_RESULT($withval)
                    az_python_use=true
                    AM_CONDITIONAL(PYTHON_USE, test x"$az_python_use" = x"true")
                    AZ_PYTHON_PREFIX( )
                fi
            ],
            [
                # --with-python was not specified.
                AC_MSG_RESULT(no)
                az_python_use=false
                AM_CONDITIONAL(PYTHON_USE, test x"$az_python_use" = x"true")
            ]
        )
    fi

])