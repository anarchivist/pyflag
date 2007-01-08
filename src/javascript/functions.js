/**
 * This array is used to remember mark status of rows in browse mode
 */
var marked_row = new Array;

/**
 * Sets/unsets the pointer and marker in browse mode (Borrowed from phpmyadmin).
 *
 * @param   object    the table row
 * @param   interger  the row number
 * @param   string    the action calling this script (over, out or click)
 * @param   string    the default background color
 * @param   string    the color to use for mouseover
 * @param   string    the color to use for marking a row
 *
 * @return  boolean  whether pointer is set or not
 */
function setPointer(theRow, theRowNum, theAction, theDefaultColor, thePointerColor, theMarkColor)
{
    var theCells = null;

    // 1. Pointer and mark feature are disabled or the browser can't get the
    //    row -> exits
    if ((thePointerColor == '' && theMarkColor == '')
        || typeof(theRow.style) == 'undefined') {
        return false;
    }

    // 2. Gets the current row and exits if the browser can't get it
    if (typeof(document.getElementsByTagName) != 'undefined') {
        theCells = theRow.getElementsByTagName('td');
    }
    else if (typeof(theRow.cells) != 'undefined') {
        theCells = theRow.cells;
    }
    else {
        return false;
    }

    // 3. Gets the current color...
    var rowCellsCnt  = theCells.length;
    var domDetect    = null;
    var currentColor = null;
    var newColor     = null;
    // 3.1 ... with DOM compatible browsers except Opera that does not return
    //         valid values with "getAttribute"
    if (typeof(window.opera) == 'undefined'
        && typeof(theRow.getAttribute) != 'undefined') {
        currentColor = theRow.getAttribute('bgcolor');
        domDetect    = true;
    }
    // 3.2 ... with other browsers
    else {
        currentColor = theRow.style.backgroundColor;
        domDetect    = false;
    } // end 3

    // 3.3 ... Opera changes colors set via HTML to rgb(r,g,b) format so fix it
    if (currentColor.indexOf("rgb") >= 0) 
    {
        var rgbStr = currentColor.slice(currentColor.indexOf('(') + 1,
                                     currentColor.indexOf(')'));
        var rgbValues = rgbStr.split(",");
        currentColor = "#";
        var hexChars = "0123456789ABCDEF";
        for (var i = 0; i < 3; i++)
        {
            var v = rgbValues[i].valueOf();
            currentColor += hexChars.charAt(v/16) + hexChars.charAt(v%16);
        }
    }

    // 4. Defines the new color
    // 4.1 Current color is the default one
    if (currentColor == ''
        || currentColor.toLowerCase() == theDefaultColor.toLowerCase()) {
        if (theAction == 'over' && thePointerColor != '') {
            newColor              = thePointerColor;
        }
        else if (theAction == 'click' && theMarkColor != '') {
            newColor              = theMarkColor;
            marked_row[theRowNum] = true;
            // Garvin: deactivated onclick marking of the checkbox because it's also executed
            // when an action (like edit/delete) on a single item is performed. Then the checkbox
            // would get deactived, even though we need it activated. Maybe there is a way
            // to detect if the row was clicked, and not an item therein...
            // document.getElementById('id_rows_to_delete' + theRowNum).checked = true;
        }
    }
    // 4.1.2 Current color is the pointer one
    else if (currentColor.toLowerCase() == thePointerColor.toLowerCase()
             && (typeof(marked_row[theRowNum]) == 'undefined' || !marked_row[theRowNum])) {
        if (theAction == 'out') {
            newColor              = theDefaultColor;
        }
        else if (theAction == 'click' && theMarkColor != '') {
            newColor              = theMarkColor;
            marked_row[theRowNum] = true;
            // document.getElementById('id_rows_to_delete' + theRowNum).checked = true;
        }
    }
    // 4.1.3 Current color is the marker one
    else if (currentColor.toLowerCase() == theMarkColor.toLowerCase()) {
        if (theAction == 'click') {
            newColor              = (thePointerColor != '')
                                  ? thePointerColor
                                  : theDefaultColor;
            marked_row[theRowNum] = (typeof(marked_row[theRowNum]) == 'undefined' || !marked_row[theRowNum])
                                  ? true
                                  : null;
            // document.getElementById('id_rows_to_delete' + theRowNum).checked = false;
        }
    } // end 4

    // 5. Sets the new color...
    if (newColor) {
        var c = null;
        // 5.1 ... with DOM compatible browsers except Opera
        if (domDetect) {
                theRow.setAttribute('bgcolor', newColor, 0);
        }
        // 5.2 ... with other browsers
        else {
	  theRow.style.backgroundColor = newColor;
        }
    } // end 5

    return true;
}

function SendAsPost(query) {
  var tmp;
  tmp=document.getElementById('pseudo_post_query');
  tmp.value=query;
  PseudoForm.submit();
};

function isMiddleClick(e) 
{
  var click;

  if (e.which) click = (e.which == 2);
  else if (e.button) click = (e.button == 4);
  
  return click;
};

function isLeftClick(e) 
{
  var click;

  if (e.which) click = (e.which == 1);
  else if (e.button) click = (e.button == 1);

  return click;
};

function tree_pane_open(left_cb,right_cb, url) {
  var w = parent.frames['right'];

  w.location.href =url +  "&callback_stored="+ right_cb+"&__pyflag_parent=" + w.__pyflag_parent + "&__pyflag_name=" + w.__pyflag_name;;
}

function tree_open(left_cb, right_cb,url) {
  var x,y;

  if (self.pageYOffset) // all except Explorer
    {
      x = self.pageXOffset;
      y = self.pageYOffset;
    }
  else if (document.documentElement && document.documentElement.scrollTop)
    // Explorer 6 Strict
    {
      x = document.documentElement.scrollLeft;
      y = document.documentElement.scrollTop;
    }
  else if (document.body) // all other Explorers
    {
      x = document.body.scrollLeft;
      y = document.body.scrollTop;
    }

  document.location.href = url + "&callback_stored="+left_cb+ "&yoffset="+y+ "&xoffset="+x + "&__pyflag_parent=" + window.__pyflag_parent + "&__pyflag_name=" + window.__pyflag_name;

  tree_pane_open(left_cb, right_cb, url);
};

/** This function is used to sumbit the query via a post to the
    target_window */
function post_link(query, target_name) {
  var target_window = find_window_by_name(target_name);
  var form = document.createElement('form');
  form.setAttribute('method','Post');
  form.setAttribute('action','/post');
  form.setAttribute('target',target_name);

  var input = document.createElement('input');

  //Ensure the new window preserves its __pyflag_parent, __pyflag_name:
  query += "&__pyflag_parent=" + target_window.__pyflag_parent + "&__pyflag_name=" + target_window.__pyflag_name;
  input.setAttribute('name','pseudo_post_query');
  input.setAttribute('value',query);
  input.setAttribute('type','hidden');
  form.appendChild(input);

  document.body.appendChild(form);
  form.submit();
};

function refresh(query, pane) {
  var target;

  if(pane=='parent') {
    target = find_window_by_name(window.__pyflag_parent);
  } else target=window;

  target.location = query + "&__pyflag_parent=" + target.__pyflag_parent + "&__pyflag_name=" + target.__pyflag_name;

  if(pane=='parent') {
    var w = find_window_by_name(window.__pyflag_name);
    w.close();
  };
};

function popup(query, callback, width, height) {
  // Derive the query string from the contents of all the form
  // elements if available:
  var f = document.forms['pyflag_form_1'];
  if(f) {
    query = 'f?';

    for(var i=0; i<f.elements.length; i++) {
      var e = f.elements[i];
      //Checkboxes should only be added if they are checked
      if(e.type=='checkbox' && !e.checked) {
	continue;
      };
      //We must leave the submit button off, so that when the popup
      //window refreshes to its parent we know it wasnt actually
      //submitted.
      if(e.type!='submit' && e.name.length>0 ) {
	query+=e.name + '=' + encodeURIComponent(e.value)+'&';
      };
    };
  };

  //Now open the window:
  var w=window.open(query+"&callback_stored="+callback + "&__pyflag_parent=" + window.__pyflag_name+"&__pyflag_name=popup" + callback,'popup'+callback, 'width='+width+', height='+height+', scrollbars=yes');
  w.parent = window.name;
};


function submit_form(pane, current_cb) {
  var target;
  var query = 'f?';

  if(pane=='parent') {
    target = find_window_by_name(window.__pyflag_parent);
    query += "__pyflag_parent=" + target.__pyflag_parent + "&__pyflag_name=" + target.__pyflag_name +"&";
 } else if(pane=='popup') {
    target = window.open('','popup'+callback, 'width=600, height=600, scrollbars=yes');
    query += "__pyflag_parent=" + window.__pyflag_name + "&__pyflag_name=popup" + callback +"&";
  } else {
    target=window;
    query += "&__pyflag_parent=" + target.__pyflag_parent + "&__pyflag_name=" + target.__pyflag_name+"&";
  };

  var f = document.forms['pyflag_form_1'];
  if(f) {
    for(var i=0; i<f.elements.length; i++) {
      var e = f.elements[i];
      //Checkboxes should only be added if they are checked
      if(e.type=='checkbox' && !e.checked) {
	continue;
      };

      // If we submit to our parent - we need to remove our cb:
      if(pane=='parent' && e.name=='callback_stored' && e.value==current_cb)
	continue;

      //We must leave the submit button off, so that when the popup
      //window refreshes to its parent we know it wasnt actually
      //submitted.
      if(e.name.length>0 ) {
	query+=e.name + '=' + encodeURIComponent(e.value)+'&';
      };
    };

    // Now submit into the target
    target.location = query;
  };

  if(pane=='parent') {
    var w = find_window_by_name(window.__pyflag_name);
    w.close();
  };
};

function getAbsolutePosition(element) {
  var r = { x: element.offsetLeft, y: element.offsetTop };
  if (element.offsetParent) {
    var tmp = getAbsolutePosition(element.offsetParent);
    r.x += tmp.x;
    r.y += tmp.y;
  }
  return r;
};

var currently_active_menupopup = 0;
var currently_active_menuitem = 0;

function displaySubMenu(submenu) {
  var popup = document.getElementById("PopupMenu"+submenu);
  var menuitem = document.getElementById('MenuBarItem'+submenu);
  if(!popup || !menuitem) {
    alert("Unable to find element PopupMenu"+submenu);
    return;
  };

  // Hide the old menu
  if(currently_active_menupopup)
    currently_active_menupopup.style.visibility = 'hidden';

  if(currently_active_menuitem)
    currently_active_menuitem.style.backgroundColor = 'transparent';
  
  currently_active_menupopup = popup;
  currently_active_menuitem = menuitem;

  // Show the current menu
  currently_active_menupopup.style.visibility = 'visible';
  currently_active_menuitem.style.backgroundColor = '#D2E4FD';

  var position = getAbsolutePosition(currently_active_menuitem);

  currently_active_menupopup.style.left = position.x;
  currently_active_menupopup.style.top = position.y + currently_active_menuitem.offsetHeight;
};

function hideSubMenus() {
  if(currently_active_menupopup)
    currently_active_menupopup.style.visibility = 'hidden';
  
  if(currently_active_menuitem)
    currently_active_menuitem.style.backgroundColor = 'transparent';
};

if(!window.name) window.name="main";

function SelectMenuItem(url) {
  var form = document.getElementById('CaseSelector');
  document.location = url + "&case=" + form.elements[0].value;
};

// We would really like to specify the height of the PyFlagPage as
// 100%-24px-32px. Is there a way to do this in css?
function AdjustHeightToPageSize(element_id) {
  var element = document.getElementById(element_id);

  if(!element) return;

  var position = getAbsolutePosition(element);

  element.style.height = window.innerHeight - position.y -1 + "px";
  element.style.overflowY = 'auto';
}

/** This searches the heirarchy of windows for a window of the given
 name.  Note that JS windows are not the same as pyflag windows. A
 Pyflag window may contain several js windows (which all have the same
 __pyflag_name and __pyflag_parent values). We return the highest
 level js window object with the specified name.
*/
function find_window_by_name(name) {
  var w=window;
  var new_w;
  var target=0;

  while(1) {
    if(w.__pyflag_name == name) { target=w;};

    //Top level window has the same name as its parent
    if(w.__pyflag_parent==w.__pyflag_name) 
      break;

    // Find the parent of this window
    new_w = w.opener;
    if(!new_w) new_w=w.parent;

    // Top level js window - this should not happen
    if(w==new_w)
      break;

    w = new_w;
    if(!w) {
      alert("No opener?");
      break;
    };
  }

  return target;
};

function link_to_parent(url, name) {
  var w = 0;

  if(!w) w=find_window_by_name(name);
  if(!w) w=window.opener;
  if(!w) w=window.parent;

  //Ensure that the target maintains its __pyflag_name, __pyflag_parent.
  w.document.location = url + "&__pyflag_parent=" + w.__pyflag_parent + "&__pyflag_name=" + w.__pyflag_name;

  // Close ourselves:
  w = find_window_by_name(window.__pyflag_name);
  if(w) w.close();
};

// This function checks that certain properties have been set:
function bug_check() {
  if(!window.__pyflag_name) alert("You didnt set __pyflag_name");
  if(!window.__pyflag_parent) alert("You didnt set __pyflag_parent");
};
