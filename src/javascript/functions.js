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
  var e;

  if (e.which) click = (e.which == 2);
  else if (e.button) click = (e.button == 4);
  
  return click;
};

function isLeftClick(e) 
{
  var click;
  var e;

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
