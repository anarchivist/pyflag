""" This module has a number of useful Time manipulation utilities
"""
import _strptime, time
from datetime import date as datetime_date
import pyflag.DB as DB

_regex_cache = {}

def strptime(data_string, format="%a %b %d %H:%M:%S %Y"):
    """Return a time struct based on the input string and the format string.

    This has been taken from the Python2.5 distribution and slightly modified.
    """
    time_re = _strptime.TimeRE()
    locale_time = time_re.locale_time
    format_regex = _regex_cache.get(format)
    if not format_regex:
        try:
            format_regex = time_re.compile(format)
        # KeyError raised when a bad format is found; can be specified as
        # \\, in which case it was a stray % but with a space after it
        except KeyError, err:
            bad_directive = err.args[0]
            if bad_directive == "\\":
                bad_directive = "%"
            del err
            raise ValueError("'%s' is a bad directive in format '%s'" %
                                (bad_directive, format))
        # IndexError only occurs when the format string is "%"
        except IndexError:
            raise ValueError("stray %% in format '%s'" % format)
        _regex_cache[format] = format_regex

    found = format_regex.match(data_string)

    if not found:
        raise ValueError("time data did not match format:  data=%s  fmt=%s" %
                         (data_string, format))

    if len(data_string) < found.end():
        raise ValueError("Not enough data to convert")

    ## The default year if not specified. Python uses 1900 but MySQL
    ## doesnt like it, this makes more sense.
    year = 2007
    month = day = 1
    hour = minute = second = 0
    tz = -1
    # Default to -1 to signify that values not known; not critical to have,
    # though
    week_of_year = -1
    week_of_year_start = -1
    # weekday and julian defaulted to -1 so as to signal need to calculate
    # values
    weekday = julian = -1
    found_dict = found.groupdict()
    for group_key in found_dict.iterkeys():
        # Directives not explicitly handled below:
        #   c, x, X
        #      handled by making out of other directives
        #   U, W
        #      worthless without day of the week
        if group_key == 'y':
            year = int(found_dict['y'])
            # Open Group specification for strptime() states that a %y
            #value in the range of [00, 68] is in the century 2000, while
            #[69,99] is in the century 1900
            if year <= 68:
                year += 2000
            else:
                year += 1900
        elif group_key == 'Y':
            year = int(found_dict['Y'])
        elif group_key == 'm':
            month = int(found_dict['m'])
        elif group_key == 'B':
            month = locale_time.f_month.index(found_dict['B'].lower())
        elif group_key == 'b':
            month = locale_time.a_month.index(found_dict['b'].lower())
        elif group_key == 'd':
            day = int(found_dict['d'])
        elif group_key == 'H':
            hour = int(found_dict['H'])
        elif group_key == 'I':
            hour = int(found_dict['I'])
            ampm = found_dict.get('p', '').lower()
            # If there was no AM/PM indicator, we'll treat this like AM
            if ampm in ('', locale_time.am_pm[0]):
                # We're in AM so the hour is correct unless we're
                # looking at 12 midnight.
                # 12 midnight == 12 AM == hour 0
                if hour == 12:
                    hour = 0
            elif ampm == locale_time.am_pm[1]:
                # We're in PM so we need to add 12 to the hour unless
                # we're looking at 12 noon.
                # 12 noon == 12 PM == hour 12
                if hour != 12:
                    hour += 12
        elif group_key == 'M':
            minute = int(found_dict['M'])
        elif group_key == 'S':
            second = int(found_dict['S'])
        elif group_key == 'A':
            weekday = locale_time.f_weekday.index(found_dict['A'].lower())
        elif group_key == 'a':
            weekday = locale_time.a_weekday.index(found_dict['a'].lower())
        elif group_key == 'w':
            weekday = int(found_dict['w'])
            if weekday == 0:
                weekday = 6
            else:
                weekday -= 1
        elif group_key == 'j':
            julian = int(found_dict['j'])
        elif group_key in ('U', 'W'):
            week_of_year = int(found_dict[group_key])
            if group_key == 'U':
                # U starts week on Sunday.
                week_of_year_start = 6
            else:
                # W starts week on Monday.
                week_of_year_start = 0
        elif group_key == 'Z':
            # Since -1 is default value only need to worry about setting tz if
            # it can be something other than -1.
            found_zone = found_dict['Z'].lower()
            for value, tz_values in enumerate(locale_time.timezone):
                if found_zone in tz_values:
                    # Deal with bad locale setup where timezone names are the
                    # same and yet time.daylight is true; too ambiguous to
                    # be able to tell what timezone has daylight savings
                    if (time.tzname[0] == time.tzname[1] and
                       time.daylight and found_zone not in ("utc", "gmt")):
                        break
                    else:
                        tz = value
                        break
    # If we know the week of the year and what day of that week, we can figure
    # out the Julian day of the year.
    if julian == -1 and week_of_year != -1 and weekday != -1:
        if week_of_year_start == 0:
            week_starts_Mon = True
        else:
            week_starts_Mon = False
        
        #week_starts_Mon = True if week_of_year_start == 0 else False

        julian = _calc_julian_from_U_or_W(year, week_of_year, weekday,
                                            week_starts_Mon)
    # Cannot pre-calculate datetime_date() since can change in Julian
    # calculation and thus could have different value for the day of the week
    # calculation.
    if julian == -1:
        # Need to add 1 to result since first day of the year is 1, not 0.
        julian = datetime_date(year, month, day).toordinal() - \
                  datetime_date(year, 1, 1).toordinal() + 1
    else:  # Assume that if they bothered to include Julian day it will
           # be accurate.
        datetime_result = datetime_date.fromordinal((julian - 1) + datetime_date(year, 1, 1).toordinal())
        year = datetime_result.year
        month = datetime_result.month
        day = datetime_result.day
    if weekday == -1:
        weekday = datetime_date(year, month, day).weekday()
    return time.struct_time((year, month, day,
                             hour, minute, second,
                             weekday, julian, tz)), found

# below are some helpful functions to deal with date and timezone translation

from dateutil.tz import gettz
from dateutil.parser import parse as du_parse
import datetime
from os.path import basename

from pyflag.FileSystem import DBFS

def get_case_tz_name(case):
    """ return the name of the current case timezone """
    dbh = DB.DBO(case)
    dbh.execute('select value from meta where property="TZ" limit 1')
    row = dbh.fetch()
    if row['value'] == "SYSTEM":
    	return None
    else:
        return row['value']

def get_case_tz(case):
    """ return the tzinfo for the current case timezone """
    return gettz(get_case_tz_name(case))

def get_evidence_tz_name(case, fd):
    """ return the name of the timezone for the given piece of evidence """
    try:
        tz = fd.gettz()
        return tz
    except AttributeError:
        pass

    ## fd is not an a File descendant, it could be a cached file
    ddfs = DBFS(case)
    fd2 = ddfs.open(inode = basename(fd.name))
    return fd2.gettz()

def parse(timestr, case=None, evidence_tz=None, **options):
    """ Parse a time string using dateutil.parser.  Current Time and Evidence
    timezone are used as a defaults for missing values on parsing. The result
    is a time string suitable for mysql expressed in case timezone """
    if not timestr:
    	return None

    evidence_tz = gettz(evidence_tz)
    case_tz = get_case_tz(case)

    DEFAULT = datetime.datetime(tzinfo=gettz("UTC"), *time.gmtime()[:6]).astimezone(evidence_tz)
    dt = du_parse(timestr, default=DEFAULT, **options).astimezone(case_tz)
    return time.strftime("%Y-%m-%d %H:%M:%S", dt.timetuple())

def convert(timeval, case=None, evidence_tz=None):
    """ Convert a datetime or time tuple from evidence timezone to case timezone """
    evidence_tz = gettz(evidence_tz)
    case_tz = get_case_tz(case)

    # convert to datetime if not already
    if isinstance(timeval, str):
        timeval = time.strptime(timeval, "%Y-%m-%d %H:%M:%S")[:-2]

    if not isinstance(timeval, datetime.datetime):
        timeval = datetime.datetime(*timeval)

    # set a timezone if none is set
    if not timeval.tzinfo:
        timeval = datetime.datetime(tzinfo=evidence_tz, *timeval.timetuple()[:6])

    dt = timeval.astimezone(case_tz)
    return time.strftime("%Y-%m-%d %H:%M:%S", dt.timetuple())
