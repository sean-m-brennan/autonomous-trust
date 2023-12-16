# AUTO GENERATED FILE - DO NOT EDIT

from dash.development.base_component import Component, _explicitize_args


class Trigger(Component):
    """A Trigger component.


Keyword arguments:

- id (string; optional)

- eventType (string; optional)

- triggers (number; default 0)"""
    _children_props = []
    _base_nodes = ['children']
    _namespace = 'async_update'
    _type = 'Trigger'
    @_explicitize_args
    def __init__(self, id=Component.UNDEFINED, eventType=Component.UNDEFINED, triggers=Component.UNDEFINED, **kwargs):
        self._prop_names = ['id', 'eventType', 'triggers']
        self._valid_wildcard_attributes =            []
        self.available_properties = ['id', 'eventType', 'triggers']
        self.available_wildcard_properties =            []
        _explicit_args = kwargs.pop('_explicit_args')
        _locals = locals()
        _locals.update(kwargs)  # For wildcard attrs and excess named props
        args = {k: _locals[k] for k in _explicit_args}

        super(Trigger, self).__init__(**args)
