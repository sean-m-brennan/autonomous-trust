
let updateDivText = function(div_info) {
	// parameter is a 2-tuple of div id and string
	$('#' + div_info[0]).text(div_info[1]);
}

let newGraphFigure = function(fig_info) {
	// parameter is a 3-tuple of graph div id, go.Figure dict, and config dict
	let data = fig_info[1]['data'];
	let layout = fig_info[1]['layout'];
	Plotly.newPlot(fig_info[0], data, layout, fig_info[2])
}

let updateGraphFigure = function(fig_info) {
	// parameter is a 3-tuple of graph div id, go.Figure dict, and config dict
	let data = fig_info[1]['data'];
	let layout = fig_info[1]['layout'];
	Plotly.react(fig_info[0], data, layout, fig_info[2])
}

 const loc = window.location;
let ws_uri;
if (loc.protocol === "https:") {
    ws_uri = "wss:";
} else {
    ws_uri = "ws:";
}
ws_uri += "//" + loc.hostname + ":5005/";

const socket = new WebSocket(ws_uri)

socket.onopen = function(e) {
    socket.send("connect");
};

socket.onmessage = function(message) {
    const obj = JSON.parse(message.data);
    switch (obj.event) {
        case "update_div_text":
            updateDivText(obj.data);
            break;
        case "new_graph_figure":
            newGraphFigure(obj.data);
            break;
        case "update_graph_figure":
            updateGraphFigure(obj.data);
            break;
    }
};