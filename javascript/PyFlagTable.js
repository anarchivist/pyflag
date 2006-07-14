dojo.provide("dojo.widget.html.PyFlagTable");
dojo.provide("dojo.widget.PyFlagTable");
dojo.require("dojo.widget.*");
dojo.require("dojo.widget.SortableTable");
dojo.require("dojo.widget.html.SortableTable");

dojo.widget.html.PyFlagTable=function() {
	//	summary
	//	Constructor for the SortableTable widget
	dojo.widget.html.SortableTable.call(this);
	this.widgetType="PyFlagTable";
	this.query='/';
};

dojo.inherits(dojo.widget.html.PyFlagTable, dojo.widget.html.SortableTable);

dojo.lang.extend(dojo.widget.html.PyFlagTable, 
		 dojo.widget.html.SortableTable);

dojo.lang.extend(dojo.widget.html.PyFlagTable, {
  onHeaderClick: function(e){
		var source=e.target;
		var div=dojo.html.getParentByType(source,"div");
		var table=dojo.widget.getWidgetById(div.id);

		//This relies on the id field being set properly
		table.setUrl("f?"+this.query+"&order="+e.target.id);
	}
  });

dojo.widget.tags.addParseTreeHandler("dojo:pyflagtable");

dojo.widget.PyFlagTable=function(){
  dojo.widget.SortableTable.call(this);
  this.widgetType="PyFlagTable";
};

dojo.inherits(dojo.widget.PyFlagTable, dojo.widget.SortableTable);
dojo.lang.extend(dojo.widget.PyFlagTable, dojo.widget.SortableTable);
