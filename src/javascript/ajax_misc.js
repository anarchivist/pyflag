/** This is a debugging aid to show a full backtrace - nice trick */
function alert_bt() {
  alert((new Error()).stack);
};

/** This function is used to set the url of a ContentPane. We cant use
    the ContentPane's set url because it either caches the page (which
    causes memory explosion in the browser) or adds rubbish to the url
    like ?dojo..preventCache=115369481689 

    widget can be a proper widget, or the name of a widget.
*/
function set_url(widget, url) { 
  if(dojo.lang.isString(widget))
    widget = dojo.widget.getWidgetById(widget); 

  if(!widget) alert("Cant find target "+widget);

  update_default_toolbar();

  //  widget.setUrl(url);
  dojo.io.bind({
    url: url+"&__pane__="+widget.widgetId,
	useCache: false,
	preventCache: false,
	method:  "GET",
	mimetype: "text/html",
	handler: function(type, data, e) {
	if(type == "load") {
	  update_default_toolbar();
	  widget.setContent(data);
	  widget.href = url;
	} else {
	  // works best when from a live server instead of from file system 
	  alert("Error contacting server. Is it down?");
	  //loading '" + url + "' (" + e.status + " "+  e.statusText + ")", "onDownloadError");
	}
      }
    });

};

function update_tree(rightcb,url,id) {
  var rightpane = dojo.widget.getWidgetById("rightpane"+id);
  if(rightpane) {
    set_url(rightpane,url+"&callback_stored="+rightcb);
  };
};

function push_on_history(container, url) {
  pyflag_history.push([container, url]);
};

/** form_name: The name of the form we should get elements from
    target: the target of this form.*/
function submitForm(form_name,target) {
  /** We try to save a get version of the current form in the
      history */
  var form = dojo.byId(form_name);
  var inputs = form.getElementsByTagName("input");
  var query = new dojo.collections.Stack();

  for(var i = 0; i < inputs.length; i++) {
    var input = inputs[i];
    if(input.name.length>0)
      query.push(input.name + '=' + input.value);
  };

  var url="f?submit=1&"+query.toArray().join("&");

  update_container(target,url);
  return;

  var kw = {
    url:	   "/f?submit=1&__pane__="+target.widgetId,
    formNode:      dojo.byId(form_name),
    load:	   function(type, data)	{
      if(target.href) {
	push_on_history("main",target.href);
      };
      update_default_toolbar();      
      container.setContent(data);
      container.href=url;
    },
    error:   function(type, error)	{ alert(String(type)+ String(error)); },
    method:  "POST",
    useCache: false,
    preventCache: false,
  };
  
  dojo.io.bind(kw);
}

function group_by(table, target) {
  var table     = document.getElementById(table);
  
  set_url(target,table.getAttribute('query') + "&dorder=Count&group_by="+last_column_name);
};

last_column_name = "";
last_table_id = 0;

function update_container(container,url) {
  var c= container;
  
  if(dojo.lang.isString(container))
    c = dojo.widget.getWidgetById(container);
  
  if(!c) return;
  c.show();

  // We must be operating on contentpanes
  //if(c.widgetType!="ContentPane") return;

  // If we are actually updating the main frame, we handle it
  // specially so the history works etc.
  if(container=="main") {
    /* Store the old url in the history */
    if(!c.pending && c.href) {
      push_on_history("main",c.href);
    };
  };

  // Ensure that we mark c as not pending:
  c.pending = false

  set_url(c,url);

  update_default_toolbar();
};


var dlg;

function init_search_dialog(e) {
  dlg = dojo.widget.byId("FilterDialog");
  var btn = document.getElementById("search_ok");
  dlg.setCloseControl(btn);
  
  btn = document.getElementById("search_cancel");
  dlg.setCloseControl(btn);
}

dojo.addOnLoad(init_search_dialog);

pyflag_history  = new dojo.collections.Stack();
pyflag_forward_history = new dojo.collections.Stack();

function update_default_toolbar() {
  // Update the toolbars to ensure the correct ones are disabled:
  var bb = dojo.widget.getWidgetById("BackButton");
  
  if(pyflag_history.count==0) {
    bb.disable();
  } else bb.enable();
  
  var fb = dojo.widget.getWidgetById("ForwardButton");
  
  if(pyflag_forward_history.count==0) {
    fb.disable();
  } else fb.enable();
};

/** Clears the toolbar and installs the default handlers */
function init_toolbar() {
  var toolbar = dojo.widget.getWidgetById("toolbar");

  //History back:
  var dojo_icon= dojo.widget.createWidget("ToolbarButton",
					  {icon: "/images/stock_left.png",
					      id: "BackButton"
					      });

  dojo_icon.disable();

  dojo.event.connect(dojo_icon, "onClick", function () {
		       // The first element on the history is the current page.
		       var tmp = pyflag_history.pop();
		       if(!tmp) {
			 this.disable();
			 return;
		       };

		       var container_name = tmp[0];
		       var url = tmp[1];
		       var container = dojo.widget.getWidgetById(container_name);

		       
		       if(!container) return;

		       // Place the current container url in the forward history.
		       pyflag_forward_history.push([container_name, container.href]);

		       update_container(container,url);
		     });

  toolbar.addChild(dojo_icon);

  //History Forward:
  var dojo_icon= dojo.widget.createWidget("ToolbarButton",
					  {icon: "/images/stock_right.png",
					      id: "ForwardButton"
					      });1
  dojo_icon.disable();

  dojo.event.connect(dojo_icon, "onClick", function () {
		       var tmp = pyflag_forward_history.pop();
		       if(!tmp) {
			 this.disable();
			 return;
		       };
		       var container_name = tmp[0];
		       var url = tmp[1];
		       var container = dojo.widget.getWidgetById(container_name);

		       if(!container) return;

		       // Push the current containers url on the history
		       if(container.href)
			 pyflag_history.push([container_name, container.href]);

		       update_container(container, url);
		     });

  toolbar.addChild(dojo_icon);
};

/** Initialise the toolbar */
dojo.addOnLoad(init_toolbar);

function filter_column(table_id) {
  var element=document.getElementById("search_name");

  element.innerHTML = last_column_name;
  last_table_id = table_id;
  dlg.show();
};

function update_filter_column() {
  var container = dojo.widget.getWidgetById("tableContainer"+last_table_id);
  var table     = document.getElementById("Table" + last_table_id);
  var search    = document.getElementById('search_expression');

  if(search.value.length>0) {
    set_url(container,"/f?"+table.getAttribute('query') + "&where_"+
	    last_column_name + "=" + search.value);
  };

  return false;
};

/** This function add a single toolbar link. A toolbar link is an icon
    which when clicked refreshes a content pane to the link 

    icon: the name of the icon which will be drawn.

    link: the url to open in the container.

    target: Is the target content pane which will be refreshed to the
    link.

    container: This is the name of the container which when unloaded
    will cause the button to disappear.

    widget_id: the id that should be assigned to the new button
    toolbar.

    toolbar_id: the id on the toolbar which needs to be used.
*/
function add_toolbar_link(icon, link, target, container, widget_id, toolbar_id) {
  var toolbar  = dojo.widget.getWidgetById(toolbar_id);
  if(!toolbar) {
    alert("Cant find toolbar "+toolbar_id);
    return;
  }

  var dojo_icon= dojo.widget.createWidget("ToolbarButton",
					  {icon: icon});
  
  dojo_icon.domNode.id = widget_id;

  var container;

  if(dojo.lang.isString(container))
    container = dojo.widget.getWidgetById(container); 

  if(!container) return;

  dojo.event.connect(dojo_icon, "onClick", function () {
		       update_container(target,link);
		     });

  // When the container is unloaded we remove this button.
  container.addOnUnLoad(function() {
			  try {
			    toolbar.domNode.removeChild(dojo_icon.domNode);
			  } catch(e) {};
			});

  toolbar.addChild(dojo_icon);
};

/** Adds a disabled button 

icon: The icon to draw
container: The container when unloaded will delete the button.
widget_id: The id of the button to be created
toolbar_id: The toolbar to add the button to
*/
function add_toolbar_disabled(icon, container,widget_id, toolbar_id) {
  var toolbar  = dojo.widget.getWidgetById(toolbar_id);
  if(!toolbar) return;

  var dojo_icon= dojo.widget.createWidget("ToolbarButton",
					  {icon: icon});

  dojo_icon.domNode.id = widget_id;
  dojo_icon.disable();

  var container;

  if(dojo.lang.isString(container))
    container = dojo.widget.getWidgetById(container); 

  if(!container) return;

  // When the container is unloaded we remove this button.
  container.addOnUnLoad(function() {
			  try {
			    toolbar.domNode.removeChild(dojo_icon.domNode);
			  } catch(e) {};
			});

  toolbar.addChild(dojo_icon);
};

function add_toolbar_callback(icon, link, target, container, toolbar_id) {
  var toolbar  = dojo.widget.getWidgetById(toolbar_id);
  if(!toolbar) return;
  var dojo_icon= dojo.widget.createWidget("ToolbarButton",
					  {icon: icon});

  
  var container;
  if(dojo.lang.isString(container))
    container = dojo.widget.getWidgetById(container); 

  if(!container) return;

  dojo_icon.domNode.id = "image"+target

  dojo.event.connect(dojo_icon, "onClick", function () {
		       set_url(container,link);
		     });

  install_toolbar_widget(container, toolbar, dojo_icon);
};

function install_toolbar_widget(container, toolbar, dojo_icon) {
  // When the ContentPane is unloaded, we remove this button:
  container.addOnUnLoad(function() {
			  try {
			    toolbar.domNode.removeChild(dojo_icon.domNode);
			  } catch(e) {};
			});

  toolbar.addChild(dojo_icon);
};

/** Returns the widget of given type found directly above the DOM
    element id 
*/
function find_widget_type_above(type,id) {
  var container; 
  var parent=document.getElementById(id);

  if(!parent) {
    return null;
  };

  while(1) {
    container = dojo.widget.getWidgetById(parent.id);

    // It has to be a dojo widget:
    if(container) {
      if(container.widgetType == "ContentPane") {
	break;
      };
    };

    if(parent==(document["body"]||document["documentElement"])){
      return null;
    };

    parent = parent.parentNode;
  };

  return container;
};

/** Searches through all the popups to see which one is targetting
    this node, and unbind them. This is needed before unloading the
    node to ensure there are no context menu popups still referencing
    the node - or weird things will happen.
*/
function remove_popups(node) {
  alert("remove_popups is deprecated");
  return;
  var popups = dojo.widget.getWidgetsByType("PopupMenu2");

  for(var i=0; i<popups.length; i++) {
    if(node) {
      if(popups[i] && popups[i].targetNodeIds==node.widgetId) {
	popups[i].unBindDomNode(popups[i].targetNodeIds);
	popups[i].destroy();

      };
    } else {
      if(popups[i] && popups[i].targetNodeIds && popups[i].targetNodeIds.length>0) {
	popups[i].unBindDomNode(popups[i].targetNodeIds);
	popups[i].destroy();	
	//alert("Deleting target "+popups[i].targetNodeIds);
      };
    };
  };
};


/** We override the popupmenu to ensure we know which object was
    clicked 
*/
dojo.lang.extend(dojo.widget.PopupMenu2, {
  onOpen: function (e){
		     this.openEvent = e;
		     
		     if(e.target.getAttribute('column')) {
		       last_column_name = e.target.getAttribute('column');
		       last_table_id = e.target.getAttribute('table_id');
		     };

		     // Ensure we are a valid popupmenu at all.
		     if(!this.domNode) return;
		     
		     //dojo.debugShallow(e);
		     this.open(e.clientX, e.clientY, null, [e.clientX, e.clientY]);
		     
		     e.preventDefault();
		     e.stopPropagation();
		   }
  });

dojo.lang.extend(dojo.widget.PopupMenu2, {
  isShowing: function() {
		     if(this.domNode)
		       return dojo.html.isShowing(this.domNode);
		   }
  });


/** Extend the ComboBox to have a default value */
dojo.lang.extend(dojo.widget.ComboBox, {
  defaultValue:'',
    
  initialize: function(args, frag) {
      dojo.widget.ComboBox.superclass.initialize.call(this, args, frag);

      if(this.defaultValue) {
	this.setValue(this.defaultValue);
      };
    },
  });

function show_popup(container, url) {
  var c = dojo.widget.getWidgetById(container);

  c.show();
  
  // Cant use setUrl due to caching problems mentioned above:
  //  c.setUrl(url);
  dojo.io.bind({
    url: url+"&__pane__="+container,
	useCache: false,
	preventCache: false,
	method:  "GET",
	mimetype: "text/html",
	handler: function(type, data, e) {
	if(type == "load") {
	  c.setContent(data);
	  c.href = url;
	} else {
	  // works best when from a live server instead of from file system 
	  c._handleDefaults.call("Error loading '" + url + "' (" + e.status + " "+  e.statusText + ")", "onDownloadError");
	}
      }
    });
};
