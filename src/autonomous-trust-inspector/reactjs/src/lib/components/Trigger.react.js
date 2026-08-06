/********************
 *  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 ********************/
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
