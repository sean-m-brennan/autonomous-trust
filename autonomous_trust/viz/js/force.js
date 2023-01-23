/**
   Dynamic graph visualization using D3 forces.
   Add/remove nodes and edges, group colors, and weighted edges.

   Requires: JQuery v3.6.1+, D3 v4, D3-legend v2.25.6
 */

createForcesGraph = function (containerSelect=".graph-container", debugging=false, with_websockets=true) {
    // only settable in constructor
    const use_ws = with_websockets;
    const debug = debugging;

    // optionally set in init()
    let max_msgs = 500;
    let ws_port = 8000;

    let msg_num = 0;
    let ws_active = false;
    let ws_init = false;
    let ws = null;
    let group_ids = null;

    const node_metadata = ["group"];
    const link_metadata = ["group", "value"];
   
    let graph = {
        nodes: [],
        links: [],
    };
    const targetElement = document.querySelector(containerSelect);
    let initialMessage = targetElement.id;
    const width = targetElement.offsetWidth ? targetElement.offsetWidth : 800;
    const height = targetElement.offsetHeight ? targetElement.offsetHeight : width * 2/3;

    let svgElt = targetElement.querySelector('svg');
    let svgPrime;
    if (svgElt == null)
        svgPrime = d3.select(targetElement).append('svg')
            .attr("width", width)
            .attr("height", height)
            .attr("xmlns", "http://www.w3.org/2000/svg")
            .attr("xml:space", "preserve");
    else
        svgPrime = d3.select(svgElt);
    const svg = svgPrime;
    const g = svg.append("g");

    let nodeGroup = g.attr("class", "nodes")
        .selectAll("circle")
        .style("opacity", 1);
    
    let linkGroup = g.attr("class", "links")
        .selectAll("line");

    const color = d3.scaleOrdinal(d3.schemeCategory20);

    const legend = svg.append("g")
        .attr("class", "legend")
        .attr("transform", "translate(20,20)scale(.5)");

    const simulation = d3.forceSimulation()
        .force("x", d3.forceX(width / 2).strength(0.4))
        .force("y", d3.forceY(height / 2).strength(0.6))
        .force("link", d3.forceLink().id(function (d) {
            return d.id;
        }))
        .force("charge", d3.forceManyBody().strength(-1000))
        .force("collide", d3.forceCollide().radius(function (d) {
            return d.r * 10;
        }))
        .force("center", d3.forceCenter(width / 2, height / 2));

    svg.append("rect")
        .attr("width", width)
        .attr("height", height)
        .style("fill", "none")
        .style("pointer-events", "all")
        .call(d3.zoom()
            .scaleExtent([1/32, 64])
            .translateExtent([[0, 0], [width, height]])
            .on("zoom", zoomed));

    function zoomed() {
        g.attr("transform", d3.event.transform);
    }

    function clear() {
        svg.selectAll("line").remove();
        svg.selectAll("circle").remove();        
    }
    
    function update() {
        clear();

        // construct dynamic graph legend
        const groupNames = group_ids == null ? 'abcdefghijklmnopqrst'.split('') : group_ids;
        let ordinal = d3.scaleOrdinal()
            .domain(groupNames)
            .range(d3.schemeCategory10);  // TODO handle if max_grp_num larger than 20

        let setLegend = d3.legendColor()
            .title("Domains")
            .shapePadding(10)
            .labels(groupNames)
            .scale(ordinal);
        legend.call(setLegend);

        // Update links
        let link = linkGroup.data(graph.links);
        
        // Enter links
        let linkEnter = link
            .enter().append("line")
            .style("stroke-width", function (d) {
                return Math.sqrt(d.value);
            })
            .style("stroke", function (d) {
                if (d.group == 0)
                    return "#777";
                return ordinal(d.group);
            });
        link = linkEnter.merge(link);
        
        // Exit any old links
        link.exit().remove();

        let node2neighbors = {};
        for (let i =0; i < graph.nodes.length; i++){
            let name = graph.nodes[i].name;
            node2neighbors[name] = graph.links.filter(function(d){
                return d.source.name === name || d.target.name === name;
            }).map(function(d){
                return d.source.name === name ? d.target.name : d.source.name;
            });
        }

        // Update the nodes
        let node = nodeGroup.data(graph.nodes);
        
        // Enter any new nodes
        let nodeEnter = node
            .enter().append("circle")
            .attr("r", 5)
            /*.style("opacity", function (d) {
                return node2neighbors[d.name].length > 0 ? 1 : 0;  // FIXME not working
            })*/
            .style("opacity", 1)
            .style("fill", function (d) {
                return ordinal(d.group);
            })
            .call(d3.drag()
                  .on("start", dragstarted)
                  .on("drag", dragged)
                  .on("end", dragended));
        
        nodeEnter.append("title")
            .text(function (d) {
                return d.id;
            });
        node = nodeEnter.merge(node);
        
        // Exit any old nodes
        node.exit().remove();

        // validate connectivity
        let node_ids = [];
        for (let n = 0; n < graph.nodes.length; n++) {
            node_ids.push(graph.nodes[n].id);
        }
        let bad_links = [];
        for (let i = 0; i < graph.links.length; i++) {
            let src = graph.links[i].source;
            let tgt = graph.links[i].target;
            if (src.hasOwnProperty("id"))
                src = src.id;
            if (tgt.hasOwnProperty("id"))
                tgt = tgt.id;
            if (!node_ids.includes(src) || !node_ids.includes(tgt)) {
                if (debug)
                    console.log("Bad link: " + src.toString() +
                        " " + tgt.toString());
                bad_links.push(graph.links[i]);
            }
        }
        if (bad_links.length > 0)
            remove_links(bad_links, false);
        
        // Redefine and restart simulation
        simulation
            .nodes(graph.nodes)
            .on("tick", ticked);
        
        simulation.force("link")
            .links(graph.links);
        
        function ticked() {
            link
                .attr("x1", function (d) {
                    return d.source.x;
                })
                .attr("y1", function (d) {
                    return d.source.y;
                })
                .attr("x2", function (d) {
                    return d.target.x;
                })
                .attr("y2", function (d) {
                    return d.target.y;
                });
            
            node
                .attr("cx", function (d) {
                    return d.x;
                })
                .attr("cy", function (d) {
                    return d.y;
                });
        }
    }
    
    function dragstarted(d) {
        if (!d3.event.active) reset(0.5);
        d.fx = d.x;
        d.fy = d.y;
    }
    
    function dragged(d) {
        d.fx = d3.event.x;
        d.fy = d3.event.y;
    }
    
    function dragended(d) {
        if (!d3.event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
    }
    
    function add_nodes(nodes) {
        for (let i = 0; i < nodes.length; i++) {
            nodes[i].x = width / 2;
            nodes[i].y = height / 2;
            graph.nodes.push(nodes[i]);
        }
        update();
    }

    function update_nodes(nodes, callback) {
        for (let i = 0; i < nodes.length; i++) {
            for (let j = 0; j < graph.nodes.length; j++) {
                if (graph.nodes[j]["id"] === nodes[i]) {
                    callback(i, j);
                    break;
                }
            }
        }
    }
    
    function remove_nodes(nodes) {
        update_nodes(nodes, function (i, j) {
            graph.nodes.splice(j, 1);
        });
        update();
    }

    function change_nodes(nodes) {
        update_nodes(nodes, function (i, j) {
            for (let prop in nodes[i]) {
                if (Object.prototype.hasOwnProperty.call(nodes[i], prop) &&
                    node_metadata.includes(prop)) {
                    graph.nodes[j][prop] = nodes[i][prop];
                }
            }
        });
        update();
    }
    
    function add_links(links) {
        for (let i = 0; i < links.length; i++) {
            graph.links.push(links[i]);
        }
        update();
    }
    
    function update_links(links, callback) {
        for (let i = 0; i < links.length; i++) {
            for (let j = 0; j < graph.links.length; j++) {
                if (graph.links[j].source.id === links[i].source &&
                    graph.links[j].target.id === links[i].target) {
                    callback(i, j);
                    break;
                }
            }
        }
    }

    function remove_links(links, with_update=true) {
        update_links(links, function (i, j) {
            graph.links.splice(j, 1);
        });
        if (with_update)
            update();
    }

    function change_links(links) {
        update_links(links, function (i, j) {
            for (let prop in links[i]) {
                if (Object.prototype.hasOwnProperty.call(links[i], prop) &&
                    link_metadata.includes(prop)) {
                    graph.links[j][prop] = links[i][prop];
                }
            }
        });
        update();
    }
    
    function plot_new_graph(graph_in) {
        // reset existing graph
        graph = {nodes: [], links: []};
        clear();
        simulation.force("link", null)
            .force("link", d3.forceLink().id(function (d) {
                return d.id;
            }));
        
        graph.links = graph_in.links
        for (let i = 0; i < graph_in.nodes.length; i++) {
            let node = graph_in.nodes[i];
            node.x = width / 2;
            node.y = height / 2;
            graph.nodes.push(node);
        }
        update();
    }
    
    function reset(speed = 0.1) {
        simulation.alphaTarget(speed).restart();
    }
    
    function process_msg(graph_in) {
        let num_nodes = graph_in.nodes.length.toString();
        let num_links = graph_in.links.length.toString();
        if ("type" in graph_in && graph_in.type === "add") {
            if (debug)
                console.log("add " + num_nodes + " nodes and " +
                            num_links + " links");
            if (graph_in.nodes.length > 0)
                add_nodes(graph_in.nodes);
            if (graph_in.links.length > 0)
                add_links(graph_in.links);
            reset();
        } else if ("type" in graph_in && graph_in.type === "remove") {
            if (debug)
                console.log("remove " + num_nodes + " nodes and " +
                            num_links + " links")
            if (graph_in.nodes.length > 0)
                remove_nodes(graph_in.nodes);
            if (graph_in.links.length > 0)
                remove_links(graph_in.links);
            reset();
        } else if ("type" in graph_in && graph_in.type === "meta") {
            if (graph_in.nodes.length > 0)
                change_nodes(graph_in.nodes);
            if (graph_in.links.length > 0)
                change_links(graph_in.links);
        } else {
            if (debug)
                console.log("full graph")
            group_ids = graph_in.groups
            plot_new_graph(graph_in);
            reset(0.3);
        }
        if (max_msgs < 1 || msg_num < max_msgs) {
            ws.send("");
            msg_num++;
        } else {
            ws.send("done");
        }
    }

    function save_svg() {
        const svgData = new XMLSerializer().serializeToString(svg.node());
        const preface = '<?xml version="1.0" standalone="no"?>\r\n';
        const svgBlob = new Blob([preface, svgData], {type:"image/svg+xml;charset=utf-8"});
        const svgUrl = URL.createObjectURL(svgBlob);
        let downloadLink = document.createElement("a");
        downloadLink.href = svgUrl;
        downloadLink.download = "graph.svg";
        document.body.appendChild(downloadLink);
        downloadLink.click();
        document.body.removeChild(downloadLink);
        if (debug)
            console.log("SVG saved as graph.svg")
    }

    return ({
        init: function (port=8000, duration=500, msg=null) {
            ws_port = port;
            max_msgs = duration;
            if (msg != null)
                initialMessage = msg;

            if (use_ws) {
                ws_active = false;
                ws = new WebSocket("ws://127.0.0.1:" + ws_port + "/ws");
                ws.onmessage = function (event) {
                    process_msg(jQuery.parseJSON(event.data));
                }
                ws.onopen = function () {
                    ws_active = true;
                    if (ws_init) {
                        ws.send(initialMessage);
                        msg_num++;
                        ws_init = false;
                    }
                    if (debug)
                        console.log("WS opened");
                }
                ws.onclose = function () {
                    ws_active = false;
                    ws_init = false;
                    if (debug)
                        console.log("WS closed");
                }
                ws.onerror = function (e) {
                    console.log(e);
                }
            }

            document.addEventListener('keypress', e => {
                //console.log(e.key)
                if (e.key === "i") {
                    simulation.stop();
                    save_svg();
                }
                else if(e.key === "n")
                    console.log("Step " + msg_num.toString());
                else if (e.key === "s")
                    stop();
            });
        },

        start: function () {
            if (use_ws) {
                if (ws_active) {
                    ws.send(initialMessage);
                    msg_num++;
                    ws_init = false;
                } else {
                    ws_init = true;
                }
            } else {
                d3.json("force.json", function (error, graph_in) {
                    if (error) throw error;
                    plot_new_graph(graph_in);
                });
            }
        },

        stop: function () {
            msg_num = max_msgs;
            ws.send("done");
            simulation.stop();
        }
    });
};


/** must have this elsewhere (or uncomment)
$(document).ready(function () {
    const forcesGraph = createForcesGraph()
    forcesGraph.init();
    forcesGraph.start();
});
*/
