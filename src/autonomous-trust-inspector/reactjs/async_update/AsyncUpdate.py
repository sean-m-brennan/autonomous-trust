# AUTO GENERATED FILE - DO NOT EDIT

from dash.development.base_component import Component, _explicitize_args


class AsyncUpdate(Component):
    """An AsyncUpdate component.


Keyword arguments:

- port (number; default 5005)"""
    _children_props = []
    _base_nodes = ['children']
    _namespace = 'async_update'
    _type = 'AsyncUpdate'
    @_explicitize_args
    def __init__(self, port=Component.UNDEFINED, **kwargs):
        self._prop_names = ['port']
        self._valid_wildcard_attributes =            []
        self.available_properties = ['port']
        self.available_wildcard_properties =            []
        _explicit_args = kwargs.pop('_explicit_args')
        _locals = locals()
        _locals.update(kwargs)  # For wildcard attrs and excess named props
        args = {k: _locals[k] for k in _explicit_args}

        super(AsyncUpdate, self).__init__(**args)
