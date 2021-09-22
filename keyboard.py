import json

class Keyboard:
    def __init__(self, one_time = False, inline = False, row_length_limit = 5):
        self.one_time = one_time
        self.inline = inline
        # ! лимит длины ряда кнопок
        self.row_length = row_length_limit
        # ! лимит количества кнопок до докам VK
        self.amount_limit = 40 if not inline else 10
        # ! лимит рядов кнопок по докам VK
        self.button_row_limit = 10 if not inline else 6
        # ! общее кол-во кнопок
        self.buttons_amount = 0
        # ! кол-во кнопок на ряду
        self.row_amount = 0
        self.buttons = [[]]
    
    def add_line(self):
        if len(self.buttons) == self.button_row_limit:
            raise Exception(f'Maximum amount of rows is {self.button_row_limit}')
        self.buttons.append([])
        self.row_amount = 0
    
    def check_buttons(self):
        if self.buttons_amount == self.amount_limit:
            raise Exception(f'Maximum amount of buttons is {self.amount_limit}')

        if self.row_amount == self.row_length:
            self.add_line()
        
    def _add_button(self, button_info, fullwidth = False):
        self.check_buttons()
        if fullwidth and self.buttons[-1]:
            self.add_line()
        
        self.buttons[-1].append(button_info)
        self.buttons_amount += 1
        self.row_amount += 1
        if fullwidth:
            self.add_line()
    
    def add_text_button(self, label, color = 'secondary', payload = None, callback = False, clear_payload = None):
        color = color.lower()
        if color not in ['primary', 'secondary', 'negative', 'positive']:
            raise Exception('Incorrect color')
        
        action = {
            'type': 'text' if not callback else 'callback',
            'label': label
        }

        if payload is not None:
            action['payload'] = {'command': payload}
        elif clear_payload is not None:
            action['payload'] = clear_payload
        
        button_info = {
            'action': action,
            'color': color
        }

        self._add_button(button_info)

    def add_link_button(self, label, url):
        button_info = {
            'action': {
                "type": "open_link",
                "link": url,
                "label": label
            }
        }
        self._add_button(button_info)
    
    def get_keyboard(self):
        if self.buttons_amount == 0:
            self.buttons = []
        
        keyboard = {
            "one_time": self.one_time,
            "inline": self.inline,
            "buttons": self.buttons
        }

        return json.dumps(keyboard, ensure_ascii=True)
    
    def __call__(self):
        return self.get_keyboard()
