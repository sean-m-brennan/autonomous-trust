/**
   Dynamic graph visualization using D3 forces.
   Add/remove nodes and edges, group colors, and weighted edges.
 */

createForcesGraph = () => {
    const debug = true;
    
    let msg_num = 0;
    const max_msgs = 500;
    const use_ws = true;
    let ws_port = 8000;
    let ws_active = false;
    let ws_init = false;
    let ws = null;
   
    let graph = {
        nodes: [],
        links: [],
    };
    const targetElement = document.querySelector('.graph-container');
    const width = targetElement.offsetWidth ? targetElement.offsetWidth : 800;
    const height = targetElement.offsetHeight ? targetElement.offsetHeight : width * 2/3;

    let transform = d3.zoomIdentity;
    
    const svg = d3.select(targetElement).append('svg')
          .attr("width", width)
          .attr("height", height);

    var g = svg.append("g");

    let nodeGroup = g.attr("class", "nodes")
        .selectAll("circle")
    
    let linkGroup = g.attr("class", "links")
        .selectAll("line")
    
    const color = d3.scaleOrdinal(d3.schemeCategory10);

    svg.append("rect")
          .attr("width", width)
          .attr("height", height)
          .style("fill", "none")
          .style("pointer-events", "all")
          .call(d3.zoom()
                .scaleExtent([1/2, 64])
                .on("zoom", zoomed));

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


    function zoomed() {
        g.attr("transform", d3.event.transform);
    }

    function clear() {
        svg.selectAll("line").remove();
        svg.selectAll("circle").remove();        
    }
    
    function update() {
        clear();

        // Update links
        var link = linkGroup.data(graph.links);
        
        // Enter links
        var linkEnter = link
            .enter().append("line")
            .style("stroke-width", function (d) {
                return Math.sqrt(d.value);
            })
            .style("stroke", function (d) {
                return color(d.group);
            });
        link = linkEnter.merge(link);
        
        // Exit any old links
        link.exit().remove();
        
        // Update the nodes
        var node = nodeGroup.data(graph.nodes);
        
        // Enter any new nodes
        var nodeEnter = node
            .enter().append("circle")
            .attr("r", 5)
            .style("fill", function (d) {
                return color(d.group);
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
        for (var i = 0; i < nodes.length; i++) {
            var node = nodes[i]
            node.x = width / 2;
            node.y = height / 2;
            graph.nodes.push(node);
        }
        update();
    }
    
    function remove_nodes(nodes) {
        for (var i = 0; i < nodes.length; i++) {
            for (var j = 0; j < graph.nodes.length; j++) {
                if (graph.nodes[j] === nodes[i]) {
                    graph.nodes.splice(j, 1);
                    break
                }
            }
        }
        update();
    }
    
    function add_links(links) {
        for (var i = 0; i < links.length; i++) {
            graph.links.push(links[i]);
        }
        update();
    }
    
    function remove_links(links) {
        for (var i = 0; i < links.length; i++) {
            for (var j = 0; j < graph.links.length; j++) {
                if (graph.links[j] === links[i]) {
                    graph.links.splice(j, 1);
                    break
                }
            }
        }
        update();
    }
    
    function plot_new_graph(graph_in) {
        // reset existing graph
        graph = {nodes: [], links: []}
        clear();
        simulation.force("link", null)
            .force("link", d3.forceLink().id(function (d) {
                return d.id;
            }));
        
        graph.links = graph_in.links
        for (var i = 0; i < graph_in.nodes.length; i++) {
            var node = graph_in.nodes[i]
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
        var num_nodes = graph_in.nodes.length.toString()
        var num_links = graph_in.links.length.toString()
        if ("type" in graph_in && graph_in.type == "add") {
            if (debug)
                console.log("add " + num_nodes + " nodes and " +
                            num_links + " links")
            if (graph_in.nodes.length > 0)
                add_nodes(graph_in.nodes);
            if (graph_in.links.length > 0)
                add_links(graph_in.links);
            reset();
        } else if ("type" in graph_in && graph_in.type == "remove") {
            if (debug)
                console.log("remove " + num_nodes + " nodes and " +
                            num_links + " links")
            if (graph_in.nodes.length > 0)
                remove_nodes(graph_in.nodes);
            if (graph_in.links.length > 0)
                remove_links(graph_in.links);
            reset();
        } else {
            if (debug)
                console.log("full graph")
            plot_new_graph(graph_in);
            reset(0.3);
        }
        if (msg_num < max_msgs) {
            ws.send("");
            msg_num++;
        }
    }

    return ({
        init: function (port=8000) {
            ws_port = port
            if (use_ws) {
                ws_active = false;
                ws = new WebSocket("ws://127.0.0.1:" + ws_port + "/ws");
                ws.onmessage = function (event) {
                    var msg = jQuery.parseJSON(event.data);
                    process_msg(msg)
                }
                ws.onopen = function (event) {
                    ws_active = true;
                    if (ws_init) {
                        ws.send("");
                        msg_num++;
                        ws_init = false;
                    }
                    if (debug)
                        console.log("WS opened");
                }
                ws.onclose = function (event) {
                    if (debug)
                        console.log("WS closed")
                }
                ws.onerror = function (e) {
                    console.log(e)
                }
            }
        },
        start: function () {
            if (use_ws) {
                if (ws_active) {
                    ws.send("");
                    msg_num++;
                    ws_init = false;
                } else {
                    ws_init = true;
                }
            } else {
                d3.json("force.json", function (error, graph_in) {
                    if (error) throw error;
                    plot_new_graph(graph_in)
                });
            }
        },
        stop: function () {
            msg_num = max_msgs
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
