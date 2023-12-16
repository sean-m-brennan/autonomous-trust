import React, {Component} from 'react';
import PropTypes from 'prop-types';
import {SocketClient} from '../socketclient.js';

export default class AsyncUpdate extends Component {
     constructor(props) {
         super(props);
         this.state = { port: props.port };
    }

    componentDidMount() {
        SocketClient.connect(this.state.port);
    }

    componentWillUnmount() {
        SocketClient.disconnect();
    }

    render() {
         return (
            <div>
            </div>
        );
    }
}

AsyncUpdate.defaultProps = {
    port: 5005,
};

AsyncUpdate.propTypes = {
    port: PropTypes.number,
};
