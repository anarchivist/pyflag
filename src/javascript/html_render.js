function getElementsByClass(searchClass,node,tag) {
  var classElements = new Array();
  if ( node == null )
    node = document;
  if ( tag == null )
    tag = '*';
  var els = node.getElementsByTagName(tag);
  var elsLen = els.length;
  var pattern = new RegExp("(^|\\s)"+searchClass+"(\\s|$)");
  for (i = 0, j = 0; i < elsLen; i++) {
    if ( pattern.test(els[i].className) ) {
      classElements[j] = els[i];
      j++;
    }
  }
  return classElements;
}

function hide_links() {
  var elements = getElementsByClass('overlay',null, 'div');

  for(var i=0; i<elements.length; i++) {
    elements[i].style.opacity = "20%";
    elements[i].style.display = "None";    
  };

  var menu = document.getElementById("pf_link_menu");
  menu.onclick = show_links;
  menu.innerHTML = "Show links";
};

function show_links() {
  var elements = getElementsByClass('overlay',null, 'div');

  for(var i=0; i<elements.length; i++) {
    elements[i].style.opacity = '1';
    elements[i].style.display = "block";
  };

  var menu = document.getElementById("pf_link_menu");
  menu.onclick = hide_links;
  menu.innerHTML = "Hide links";
}
