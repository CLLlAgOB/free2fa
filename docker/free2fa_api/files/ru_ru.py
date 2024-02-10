# ru_ru.py
# Copyright (C) 2024 Voloskov Aleksandr Nikolaevich

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
""" Модуль, содержащий сообщения на русском языке для приложения. """

MESSAGES = {
    "start": "Привет! Ваш telegram_id: {}.",
    "register_with_admin": ("📱 Для регистрации свяжитесь с админом, "
                            "и предоставьте свой telegram_id."),
    "auth_request": ("🔐 Запрос на авторизацию. Если вы не пытались войти в систему, "
                     "отклоните запрос и свяжитесь с администратором."),
    "was_auth_request": ("❌ Была произведена попытка входа но отклонена по таймауту. "
                         "Если вы не пытались войти в систему, отклоните запрос и "
                         "свяжитесь с администратором."),
    "action_accept": "\U0001f7e2 Подтвердить",
    "action_reject": "\U0001f534 Отклонить"
}
