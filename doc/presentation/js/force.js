// This is adapted from https://bl.ocks.org/mbostock/2675ff61ea5e063ede2b5d63c08020c7
// via networkx

var forcesGraph = {
    graph: {
        nodes: [],
        links: [],
    },
    svg: null,
    width: 800,
    height: 600,
    simulation: null,
    ws: null,
    msg_num: 0,
    max_msgs: 100,
    use_ws: true,
    ws_port: 8000,
    initialized: false,
};

(function () {
        var targetElement = document.querySelector('.graph-container');

        forcesGraph.width = targetElement.offsetWidth;
        forcesGraph.height = forcesGraph.width * 3 / 4;

        forcesGraph.svg = d3.select(targetElement).append('svg')
            .attr("width", forcesGraph.width)
            .attr("height", forcesGraph.height);

        forcesGraph.simulation = d3.forceSimulation()
            .force("x",d3.forceX(forcesGraph.width/2).strength(0.4))
            .force("y",d3.forceY(forcesGraph.height/2).strength(0.6))
            .force("link", d3.forceLink().id(function (d) { return d.id; }))
            .force("charge", d3.forceManyBody().strength(-1000))
            .force("collide",d3.forceCollide().radius(function (d) { return d.r * 10; }))
            .force("center", d3.forceCenter(forcesGraph.width / 2, forcesGraph.height / 2));

        forcesGraph.update = function (first = false) {
            this.svg.selectAll("*").remove();

            // Update links
            var link = forcesGraph.svg.append("g")
                .attr("class", "links")
                .selectAll("line")
                .data(this.graph.links);

            // Enter links
            var linkEnter = link.enter().append("line");
            if (first)
                link = linkEnter
            else
                link = linkEnter.merge(link);

            // Exit any old links
            link.exit().remove();

            // Update the nodes
            var node = forcesGraph.svg.append("g")
                .attr("class", "nodes")
                .selectAll("circle")
                .data(this.graph.nodes);

            // Enter any new nodes
            var nodeEnter = node
                .enter().append("circle")
                .attr("r", 5)
                .call(d3.drag()
                    .on("start", this.dragstarted)
                    .on("drag", this.dragged)
                    .on("end", this.dragended));

            nodeEnter.append("title")
                .text(function (d) {
                    return d.id;
                });
            node = nodeEnter.merge(node);

            // Exit any old nodes
            node.exit().remove();

            // Redefine and restart simulation
            this.simulation
                .nodes(this.graph.nodes)
                .on("tick", ticked);

            this.simulation.force("link")
                .links(this.graph.links);

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

        forcesGraph.dragstarted = function (d) {
            if (!d3.event.active) forcesGraph.simulation.alphaTarget(0.5).restart();
            d.fx = d.x;
            d.fy = d.y;
        }

        forcesGraph.dragged = function (d) {
            d.fx = d3.event.x;
            d.fy = d3.event.y;
        }

        forcesGraph.dragended = function (d) {
            if (!d3.event.active) forcesGraph.simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }

        forcesGraph.add_nodes = function (nodes) {
            for (var i = 0; i < nodes.length; i++) {
                this.graph.nodes.push(nodes[i]);
            }
            this.update();
        }

        forcesGraph.remove_nodes = function (nodes) {
            for (var i = 0; i < nodes.length; i++) {
                for (var j = 0; j < this.graph.nodes.length; j++) {
                    if (this.graph.nodes[j] === nodes[i]) {
                        this.graph.nodes.splice(j, 1);
                        break
                    }
                }
            }
            this.update();
        }

        forcesGraph.add_links = function (links) {
            for (var i = 0; i < links.length; i++) {
                this.graph.links.push(links[i]);
            }
            this.update();
        }

        forcesGraph.remove_links = function (links) {
            for (var i = 0; i < links.length; i++) {
                for (var j = 0; j < this.graph.links.length; j++) {
                    if (this.graph.links[j] === links[i]) {
                        this.graph.links.splice(j, 1);
                        break
                    }
                }
            }
            this.update();
        }

        forcesGraph.reset = function () {
            this.simulation.alphaTarget(0.1).restart();
        }

        forcesGraph.plot_new_graph = function (graph) {
            // reset existing graph
            this.graph = {nodes: [], links: []}
            this.svg.selectAll("*").remove();
            this.simulation.force("link", null)
                .force("link", d3.forceLink().id(function (d) {
                    return d.id;
                }));

            this.graph = graph
            this.update();

            if (self.initialized)
                this.reset();
            else
                self.initialized = true;
        }

        forcesGraph.process_msg = function (graph) {
            if ("type" in graph && graph.type == "add") {
                console.log("add " + graph.nodes.length.toString() + " nodes and " + graph.links.length.toString() + " links")
                if (graph.nodes.length > 0)
                    this.add_nodes(graph.nodes);
                if (graph.links.length > 0)
                    this.add_links(graph.links);
                this.reset();
            } else if ("type" in graph && graph.type == "remove") {
                console.log("remove " + graph.nodes.length.toString() + " nodes and " + graph.links.length.toString() + " links")
                if (graph.nodes.length > 0)
                    this.remove_nodes(graph.nodes);
                if (graph.links.length > 0)
                    this.remove_links(graph.links);
                this.reset();
            } else {
                console.log("full graph")
                this.plot_new_graph(graph);
            }
            if (this.msg_num < this.max_msgs) {
                this.ws.send("");
                this.msg_num++;
            }
        }

        forcesGraph.run = function () {
            if (this.use_ws) {
                this.ws = new WebSocket("ws://127.0.0.1:" + this.ws_port + "/ws");
                this.ws.onmessage = function (event) {
                    var graph = jQuery.parseJSON(event.data);
                    forcesGraph.process_msg(graph)
                }
                this.ws.onopen = function (event) {
                    console.log("WS opened")
                    startGraphSim() // FIXME
                }
                this.ws.onclose = function (event) {
                    console.log("WS closed")
                }
                this.ws.onerror = function (e) {
                    console.log(e)
                }
            } else {
                d3.json("force.json", function (error, graph) {
                    if (error) throw error;
                    this.plot_new_graph(graph)
                });
            }
        }
    }
)
();

function startGraphSim() {
    forcesGraph.ws.send("")
    forcesGraph.msg_num++
}

function stopGraphSim() {
    forcesGraph.msg_num = forcesGraph.max_msgs
}

$(document).ready(function () {
    forcesGraph.run();
});
