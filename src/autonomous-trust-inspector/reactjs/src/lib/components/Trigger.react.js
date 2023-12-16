import React, {Component} from 'react';
import PropTypes from 'prop-types';
import ReactDOM from 'react-dom';
import {SocketClient} from "../socketclient";

export default class Trigger extends Component {
     constructor(props) {
         super(props);
         this.state = {
             triggers: props.triggers,
         };
         this.handleEvent = this.handleEvent.bind(this);
         this.state.triggers = 0;
    }

    componentDidMount() {
        ReactDOM.findDOMNode(this).addEventListener(this.props.eventType, this.handleEvent);
        SocketClient.connect(this.state.port);
    }

    componentWillUnmount() {
        SocketClient.disconnect();
        ReactDOM.findDOMNode(this).removeEventListener(this.props.eventType, this.handleEvent);
    }

    handleEvent(event) {
        if (event.target.id === this.props.id && event.type === this.props.eventType)
            this.state.triggers++;
        this.props.setProps({ triggers: this.state.triggers });
        this.state.triggers = 0;
    }

    render() {
         const id = this.props.id;
         return (
            <div id={id}>
            </div>
        );
    }
}

Trigger.defaultProps = {
    triggers: 0,
};

Trigger.propTypes = {
    id: PropTypes.string,
    eventType: PropTypes.string,
    triggers: PropTypes.number,
    /**
     * Dash-assigned callback that should be called to report property changes
     * to Dash, to make them available for callbacks.
     */
    setProps: PropTypes.func
};
