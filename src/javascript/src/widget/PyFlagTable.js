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
	this.global_id =0;
};

dojo.inherits(dojo.widget.html.PyFlagTable, dojo.widget.html.SortableTable);

dojo.lang.extend(dojo.widget.html.PyFlagTable, 
		 dojo.widget.html.SortableTable);

dojo.lang.extend(dojo.widget.html.PyFlagTable, {
  onHeaderClick: function(e){
		var table=dojo.widget.getWidgetById("tableContainer"+
						    this.global_id);

		if(this.sortDirection) {
		  parameter='dorder';
		} else {
		  parameter='order';
		};

		url = "f?"+this.query+"&"+parameter+"="+e.target.id;
		//		alert(url);
		//This relies on the id field being set properly
		table.setUrl(url);
		   },
  onRightClick: function(e) {
		     var row=dojo.html.getParentByType(e.target,"tr");
		     var peers=row.getElementsByTagName("td");
		     var thead=dojo.html.getParentByType(row,"table");
		     var headers=thead.getElementsByTagName("th");

		     // Find the column header for the selected event:
		     
		     for(var i=0; i<peers.length; i++) {
		       if(peers[i]==e.target) {
			 last_column_name = headers[i].innerHTML;
			 last_table_id = thead.id;
			 return;
		       };
		     };
		   },
  parseColumns: function(/* HTMLTableHeadElement */ node){
		     dojo.widget.html.PyFlagTable.superclass.parseColumns.call(this, node);

		     // This ensures that all columns copy their markup directly.
		     for(i=0; i<this.columns.length; i++) {
		       this.columns[i].sortType="__markup__";
		     };
		   },
  render:function(bDontPreserve){
		var data=[]
		var body=this.domNode.getElementsByTagName("tbody")[0];

		if(!bDontPreserve){
			//	rebuild data and selection
			this.parseDataFromTable(body);
		}

		//	clone this.data for sorting purposes.
		for(var i=0; i<this.data.length; i++){
			data.push(this.data[i]);
		}

		//	build the table and pop it in.
		while(body.childNodes.length>0) body.removeChild(body.childNodes[0]);
		for(var i=0; i<data.length;i++){
			var row=document.createElement("tr");
			dojo.html.disableSelection(row);
			if (data[i][this.valueField]){
				row.setAttribute("value",data[i][this.valueField]);
			}

			//FIXME: Work out the regular pyflag
			//selection/hilighting algorithm
			if(this.isSelected(data[i])){
				row.className=this.rowSelectedClass;
				row.setAttribute("selected","true");
			} else {
				if(this.enableAlternateRows&&i%2==1){
					row.className=this.rowAlternateClass;
				}
			}

			for(var j=0;j<this.columns.length;j++){
				var cell=document.createElement("td");
				cell.setAttribute("align", this.columns[j].align);
				cell.setAttribute("valign", this.columns[j].valign);
				dojo.html.disableSelection(cell);

				//FIXME: CSS to highlight selected column
				if(this.sortIndex==j){
					cell.className=this.columnSelected;
				}

				
				cell.innerHTML=data[i][this.columns[j].getField()];			  		        row.appendChild(cell);
			}
			body.appendChild(row);
			dojo.event.connect(row, "onclick", this, "onUISelect");
			dojo.event.connect(row, "oncontextmenu", this, "onRightClick");
		}
	},
  });

dojo.widget.tags.addParseTreeHandler("dojo:pyflagtable");

dojo.widget.PyFlagTable=function(){
  dojo.widget.SortableTable.call(this);
  this.widgetType="PyFlagTable";
};

dojo.inherits(dojo.widget.PyFlagTable, dojo.widget.SortableTable);
dojo.lang.extend(dojo.widget.PyFlagTable, dojo.widget.SortableTable);
