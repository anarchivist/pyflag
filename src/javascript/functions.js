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
  parent.frames['right'].location.href =url +  "&callback_stored="+ right_cb;
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

  document.location = url + "&callback_stored="+left_cb+ "&yoffset="+y+ "&xoffset="+x;;

  tree_pane_open(left_cb, right_cb, url);
};

/** This function is used to sumbit the query via a post to the
    target_window */
function post_link(query, target_window) {
  var form = document.createElement('form');
  form.setAttribute('method','Post');
  form.setAttribute('action','/post');

  if(target_window)
    form.setAttribute('target',target_window);
  
  var input = document.createElement('input');
  input.setAttribute('name','pseudo_post_query');
  input.setAttribute('value',query);
  input.setAttribute('type','hidden');
  form.appendChild(input);

  document.body.appendChild(form);
  form.submit();
};

function xxxpopup(query, callback) {
  var f = document.forms['pyflag_form_1'];
  // There is a form already
  if(f) {
    // We just need to append the query, and force the form to be
    // submitted to the popup:
    var w = window.open('','popup'+callback, 'width=600, height=600, scrollbars=yes');
    var old_target = f.target;
    f.target = 'popup'+callback;

    var input = document.createElement('input');
    input.setAttribute('name','callback_stored');
    input.setAttribute('value',callback);
    input.setAttribute('type','hidden');
    f.appendChild(input);
    
    f.submit();
  } else {
    window.open(query + "&callback_stored=" + callback,'popup', 'width=600, height=600, scrollbars=yes');
  };
};

function refresh(query, pane) {
  var target;

  if(pane=='parent') {
    target = window.opener;
  } else target=window;

  target.location = query;

  if(pane=='parent')
    window.close();
};

function popup(query, callback) {
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
  w=window.open(query+"&__pane__=popup"+callback+"&callback_stored="+callback,'popup'+callback, 'width=600, height=600, scrollbars=yes');
  w.parent = window.name;
};


function submit_form(pane, current_cb) {
  var target;
  query = 'f?';

  if(pane=='parent') {
    target = window.opener;
  } else if(pane=='popup') {
    target = window.open('','popup'+callback, 'width=600, height=600, scrollbars=yes');
    query += "__pane__=popup"+callback;
  } else target=window;

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

  if(pane=='parent')
    window.close();
};
