function update_tree(rightcb,url) {
  var rightpane = dojo.widget.getWidgetById("rightpane");
  rightpane.setUrl(url+"&callback_stored="+rightcb);
};

function update_main(url) {
  var main = dojo.widget.getWidgetById("main");
  var toolbar = dojo.widget.getWidgetById("toolbar");
  
  dojo.dom.removeChildren(toolbar.domNode);
  main.setUrl(url);
};

function submitForm(form_name) {
  
  var kw = {
    url:	   "/f",
    formNode:dojo.byId(form_name),
    load:	   function(type, data)	{
      var main = dojo.widget.getWidgetById("main");
      var toolbar = dojo.widget.getWidgetById("toolbar");
      
      dojo.dom.removeChildren(toolbar.domNode);
      main.setContent(data);
    },
    error:   function(type, error)	{ alert(String(type)+ String(error)); },
    method:  "POST",
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
function add_toolbar_link(icon, link) {
  var toolbar  = dojo.widget.getWidgetById("toolbar");
  var dojo_icon= dojo.widget.createWidget("ToolbarButton",
					  {icon: icon})

  dojo.event.connect(dojo_icon, "onClick", function () {
			 alert(link);
		       });
  toolbar.addChild(dojo_icon);
};
