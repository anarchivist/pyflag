
/** This function is used to set the url of a ContentPane. We cant use
    the ContentPane's set url because it either caches the page (which
    causes memory explosion in the browser) or add
    ?dojo..preventCache=115369481689 */
function set_url(widget, url) { 
  update_default_toolbar();

  widget.setUrl(url);

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

function update_main(url) {
  var main = dojo.widget.getWidgetById("main");

  /* Store the old url in the history */
  if(main.href) {
    push_on_history("main",main.href);
  };

  remove_popups();

  set_url(main,url);
};

function submitForm(form_name,id) {

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

  var url="/f?"+query.toArray().join("&");
  var container = find_widget_type_above("ContentPane",id);

  var kw = {
    url:	   "/f",
    formNode:      dojo.byId(form_name),
    load:	   function(type, data)	{
      if(container.href) {
	push_on_history("main",container.href);
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

function group_by(table_id) {
  var container = dojo.widget.getWidgetById("tableContainer"+table_id);
  var table     = document.getElementById("Table" + table_id);
  
  remove_popups(container);
  set_url(container,table.getAttribute('query') + "&dorder=Count&group_by="+last_column_name);
};

last_column_name = "";
last_table_id = 0;

function update_container(container,url) {
  var c= container;
  
  if(dojo.lang.isString(container))
    c = dojo.widget.getWidgetById(container);
  
  // We must be operating on contentpanes
  if(c.widgetType!="ContentPane") return;

  remove_popups(c);

  // If we are actually updating the main frame, we handle it
  // specially so the history works etc.
  if(container=="main") 
    update_main(url);
  else
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

		       set_url(container,url);
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

		       set_url(container, url);
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

  remove_popups(container);

  if(search.value.length>0) {
    set_url(container,"/f?"+table.getAttribute('query') + "&where_"+
	    last_column_name + "=" + search.value);
  };

  return false;
};

/** This function add a single toolbar link. A toolbar link is an icon
    which when clicked refreshes the main frame to the link */
function add_toolbar_link(icon, link, id) {
  var toolbar  = dojo.widget.getWidgetById("toolbar");
  var dojo_icon= dojo.widget.createWidget("ToolbarButton",
					  {icon: icon});
  var container = find_widget_type_above("ContentPane",id);

  if(!container) return;

  dojo.event.connect(dojo_icon, "onClick", function () {
		       set_url(container,link);
		     });

  install_toolbar_widget(container, toolbar, dojo_icon);
};

/** Adds a disabled button */
function add_toolbar_disabled(icon, id) {
  var toolbar  = dojo.widget.getWidgetById("toolbar");
  var dojo_icon= dojo.widget.createWidget("ToolbarButton",
					  {icon: icon});

  var container = find_widget_type_above("ContentPane",id);

  if(!container) return;

  dojo_icon.disable();

  install_toolbar_widget(container, toolbar, dojo_icon);
  toolbar.addChild(dojo_icon);
};

function add_toolbar_callback(icon, link, id) {
  var toolbar  = dojo.widget.getWidgetById("toolbar");
  var dojo_icon= dojo.widget.createWidget("ToolbarButton",
					  {icon: icon});

  var container = find_widget_type_above("ContentPane",id);

  if(!container) return;

  dojo.event.connect(dojo_icon, "onClick", function () {
		       update_container(container.domNode.id,link);
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
  var popups = dojo.widget.getWidgetsByType("PopupMenu2");

  for(var i=0; i<popups.length; i++) {
    if(node) {
      if(popups[i] && popups[i].targetNodeIds==node.widgetId) {
	popups[i].unBindDomNode(popups[i].targetNodeIds);
	popups[i].destroyRendering();
      };
    } else {
      if(popups[i] && popups[i].targetNodeIds && popups[i].targetNodeIds.length>0) {
	popups[i].unBindDomNode(popups[i].targetNodeIds);
	popups[i].destroyRendering();	
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

		     //dojo.debugShallow(e);
		     this.open(e.clientX, e.clientY, null, [e.clientX, e.clientY]);
		     
		     if(e["preventDefault"]){
		       e.preventDefault();
		     }
		   }
  });
