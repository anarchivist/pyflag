function update_tree(rightcb,url) {
  var rightpane = dojo.widget.getWidgetById("rightpane");
  rightpane.setUrl(url+"&callback_stored="+rightcb);
};

function update_main(url) {
  var main = dojo.widget.getWidgetById("main");
  main.setUrl(url);
};

function submitForm(form_name) {
  
  var kw = {
    url:	   "/f",
    formNode:dojo.byId(form_name),
    load:	   function(type, data)	{
      var main = dojo.widget.getWidgetById("main");
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

function update_container(container,url) {
  var c = dojo.widget.getWidgetById(container);
  c.setUrl(url);
};


var dlg;
function init_search_dialog(e) {
  dlg = dojo.widget.byId("FilterDialog");
  var btn = document.getElementById("hider");
  dlg.setCloseControl(btn);
}

dojo.addOnLoad(init_search_dialog);

function filter_column(table_id) {
  var container = dojo.widget.getWidgetById("tableContainer"+table_id);
  var input = dojo.widget.getWidgetById("search_dialog_table");

  alert(input);

  dlg.show();
  //  container.setUrl(table.query + "&dorder=Count&group_by="+last_column_name);
};
