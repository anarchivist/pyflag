function update_tree(rightcb,url,id) {
  var rightpane = dojo.widget.getWidgetById("rightpane"+id);
  if(rightpane) {
    rightpane.setUrl(url+"&callback_stored="+rightcb);
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

  clear_toolbar();
  main.setUrl(url);
};

/** Clears the toolbar and installs the default handlers */
function clear_toolbar() {
  var toolbar = dojo.widget.getWidgetById("toolbar");

  dojo.dom.removeChildren(toolbar.domNode);

  //History back:
  var dojo_icon= dojo.widget.createWidget("ToolbarButton",
					  {icon: "/images/stock_left.png"});

  if(pyflag_history.count==0) {dojo_icon.disable() };
  
  dojo.event.connect(dojo_icon, "onClick", function () {
		       // The first element on the history is the current page.
		       var tmp = pyflag_history.pop();
		       var container_name = tmp[0];
		       var url = tmp[1];
		       var container = dojo.widget.getWidgetById(container_name);

		       
		       if(!container) return;

		       // Place the current container url in the forward history.
		       pyflag_forward_history.push([container_name, container.href]);

		       clear_toolbar();
		       container.setUrl(url);
		     });
  toolbar.addChild(dojo_icon);

  //History Forward:
  var dojo_icon= dojo.widget.createWidget("ToolbarButton",
					  {icon: "/images/stock_right.png"});1

  if(pyflag_forward_history.count==0) {dojo_icon.disable() };

  dojo.event.connect(dojo_icon, "onClick", function () {
		       var tmp = pyflag_forward_history.pop();
		       var container_name = tmp[0];
		       var url = tmp[1];
		       var container = dojo.widget.getWidgetById(container_name);

		       if(!container) return;

		       // Push the current containers url on the history
		       if(container.href)
			 pyflag_history.push([container_name, container.href]);

		       clear_toolbar();
		       container.setUrl(url);
		     });
  toolbar.addChild(dojo_icon);

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

  if(container.href) {
    push_on_history("main",container.href);
  };

  var kw = {
    url:	   "/f",
    formNode:      dojo.byId(form_name),
    load:	   function(type, data)	{
      clear_toolbar();
      container.setContent(data);
      container.href=url;
    },
    error:   function(type, error)	{ alert(String(type)+ String(error)); },
    method:  "POST",
    useCache: false,
  };
  
  dojo.io.bind(kw);
}

function group_by(table_id) {
  var container = dojo.widget.getWidgetById("tableContainer"+table_id);
  var table     = dojo.widget.getWidgetById("Table" + table_id);
  
  container.setUrl(table.query + "&dorder=Count&group_by="+last_column_name);
};

last_column_name = "";
last_table_id = 0;
function update_container(container,url) {
  var c = dojo.widget.getWidgetById(container);
  
  // If we are actually updating the main frame, we handle it
  // specially so the history works etc.
  if(c && container=="main") 
    update_main(url);
  else
    c.setUrl(url);
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

function filter_column(table_id) {
  var element=document.getElementById("search_name");

  element.innerHTML = last_column_name;
  last_table_id = table_id;
  dlg.show();
};

function update_filter_column() {
  var container = dojo.widget.getWidgetById("tableContainer"+last_table_id);
  var table     = dojo.widget.getWidgetById("Table" + last_table_id);
  var search    = document.getElementById('search_expression');

  if(search.value.length>0) {
    container.setUrl("/f?"+table.query + "&where_"+last_column_name +
		     "=" + search.value);
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
		       container.setUrl(link);
		     });
  toolbar.addChild(dojo_icon);
};

/** Adds a disabled button */
function add_toolbar_disabled(icon) {
  var toolbar  = dojo.widget.getWidgetById("toolbar");
  var dojo_icon= dojo.widget.createWidget("ToolbarButton",
					  {icon: icon});

  dojo_icon.disable();
  toolbar.addChild(dojo_icon);
};

/** Returns the widget of given type found directly above the DOM
    element id 
*/
function find_widget_type_above(type,id) {
  var container; 
  var parent=document.getElementById(id);

  if(!parent) {
    alert("Cant find id "+id);
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

function add_toolbar_callback(icon, link, id) {
  var toolbar  = dojo.widget.getWidgetById("toolbar");
  var dojo_icon= dojo.widget.createWidget("ToolbarButton",
					  {icon: icon});

  var container = find_widget_type_above("ContentPane",id);

  if(!container) return;

  dojo.event.connect(dojo_icon, "onClick", function () {
		       update_container(container.domNode.id,link);
		     });
  toolbar.addChild(dojo_icon);
};
