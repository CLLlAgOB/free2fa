# main.py
# Copyright (C) 2024 Voloskov Aleksandr Nikolaevich

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
"""The main module includes a bot and an api."""

import time
import logging
import asyncio
import aiosqlite
import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from aiogram import Bot, types, Dispatcher
from aiogram.dispatcher.router import Router
from aiogram.filters import Command
from aiogram import exceptions as aiogram_exceptions
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.client.session.aiohttp import AiohttpSession
from config import Config


if Config.LANGUAGE == 'ru':
    import ru_ru as loc
elif Config.LANGUAGE == 'en':
    import en_en as loc
else:
    # default value if language is not defined
    import en_en as loc

router = Router()

# FastAPI and aiogram initialization
app = FastAPI()
bot = Bot(token=Config.TOKEN, session=AiohttpSession(timeout=3))
dp = Dispatcher()
dp.include_router(router)

# Other dictionaries
auth_requests = {}
last_message_info = {}

# Server Responses


def response_200():
    """Response api code 200 OK"""
    return JSONResponse(status_code=200, content={"Reply-Message": "OK"})


def response_403():
    """Response api code 403 Forbidden"""
    return JSONResponse(status_code=403, content={"Reply-Message": "Forbidden"})


def response_404():
    """Response api code 404 Not Found"""
    return JSONResponse(status_code=403, content={"Reply-Message": "Not Found"})


def response_408():
    """Response api code 408 Timeout"""
    return JSONResponse(status_code=403, content={"Reply-Message": "Timeout"})


class ClientKeyStorage:
    """API key control class"""
    _client_key = None

    @classmethod
    def verify_and_set_key(cls, key):
        """Validates the key and sets it if it is the first key. Returns the validation status."""
        if cls._client_key is None:
            cls._client_key = key
            logger.info("API KEY installed..")
            return "set"
        elif cls._client_key == key:
            return "valid"
        else:
            logger.warning("Invalid API KEY")
            return "invalid"


class AuthenticateRequest(BaseModel):
    """Defining a Pydantic model class for a query /authenticate"""
    user_name: str
    client_key: str


class MessageLimiter:
    """Configuring the message limit and queue."""
    # The Telegram API limits 30 messages per second, if more than that, it pauses for 5 seconds.
    max_messages_per_second = 30
    message_count = 0
    message_count_lock = asyncio.Lock()

    @classmethod
    async def reset_message_count(cls):
        """Reset the count of messages every second."""
        while True:
            await asyncio.sleep(1)
            cls.message_count = 0

    @classmethod
    async def wait_for_message_slot(cls):
        """Wait until there is a free slot for sending a message."""
        async with cls.message_count_lock:
            while cls.message_count >= cls.max_messages_per_second:
                await asyncio.sleep(1)
            cls.message_count += 1


# Bot and application configuration
DATABASE_PATH = '/opt/db/users.db'

LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT,
                    datefmt="%Y-%m-%d %H:%M:%S")

logger = logging.getLogger("free2fa4rdg")


logging_config = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "()": "uvicorn.logging.DefaultFormatter",
            "fmt": LOG_FORMAT,
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
    },
}

# =============DB============


async def find_user_by_domain(domain_and_username):
    """Searching for a user in the database"""
    logger.debug("Search for a user with the name: %s", domain_and_username)
    async with aiosqlite.connect(DATABASE_PATH) as db_connection:
        logger.debug("Successful connection to the database")
        query = (
            "SELECT telegram_id, is_bypass "
            "FROM users "
            "WHERE domain_and_username = ?"
        )
        async with db_connection.execute(query, (domain_and_username,)) as cursor:
            result = await cursor.fetchone()
            if result:
                telegram_id, is_bypass = result
                logger.debug("Found User: %s tg id: %s is_bypass: %s",
                             domain_and_username, telegram_id, is_bypass)
                return telegram_id, is_bypass
            logger.warning("User %s not found", domain_and_username)
        return None, None


async def create_new_user(domain_and_username, telegram_id, is_bypass=False):
    """Create a new user in the database"""
    async with aiosqlite.connect(DATABASE_PATH) as db_connection:
        query = (
            "INSERT INTO users (domain_and_username, telegram_id, is_bypass) "
            "VALUES (?, ?, ?)"
        )
        try:
            await db_connection.execute(query, (domain_and_username, telegram_id, is_bypass))
            await db_connection.commit()
            return True
        except aiosqlite.IntegrityError:
            return False


# ====api===

@app.post("/authenticate")
async def authenticate_user(request: AuthenticateRequest):
    """Authenticate, waiting for a response."""
    # Проверка API ключа
    client_key = request.client_key
    key_status = ClientKeyStorage.verify_and_set_key(client_key)

    if key_status == "invalid":
        return response_403()
    if key_status == "set" and request.user_name == "key":
        return response_200()

    if request.user_name == "":
        # user_name is missing
        return response_404()

    normalized_username = request.user_name.lower()
    logger.debug("app.post authenticate  User verification: %s",
                 normalized_username)
    telegram_id, is_bypass = await find_user_by_domain(normalized_username)
    logger.debug("app.post authenticate  Found Telegram ID: %s", telegram_id)

    if telegram_id and telegram_id != 0 and not is_bypass:
        return await handle_auth_with_wait(normalized_username, telegram_id)
    else:
        return await handle_auto_reg_or_bypass(normalized_username, telegram_id, is_bypass)


async def handle_auth_with_wait(normalized_username, telegram_id):
    """
    Waits for user authentication confirmation. Sends an authentication request
    and waits for a response for the specified time. Returns the appropriate HTTP response
    depending on the authentication result.

    :param normalized_username: Normalized username.
    :param telegram_id: User ID in Telegram.
    :return: HTTPResponse depending on the authentication result.
    """
    wait_time = 1  # Initial waiting time
    max_wait_time = Config.FREE2FA_TIMEOUT
    await send_auth_request(telegram_id, normalized_username)

    while wait_time <= max_wait_time and normalized_username not in auth_requests:
        logger.debug("Waiting for a response for %s seconds %.1f from %d",
                     normalized_username, wait_time, max_wait_time)
        await asyncio.sleep(0.5)
        wait_time += 0.5

    if auth_requests.get(normalized_username):
        logger.info("Authentication request accepted by user %s",
                    normalized_username)
        asyncio.create_task(clear_auth_request(normalized_username))
        return response_200()
    else:
        logger.info(
            "Authentication request rejected or timeout for user: %s", normalized_username)
        asyncio.create_task(clear_auth_request(normalized_username))
        return response_403() if normalized_username in auth_requests else response_408()


async def handle_auto_reg_or_bypass(normalized_username, telegram_id, is_bypass):
    """
    Handles auto-registration or authentication bypass for a user.
    Depending on configuration conditions and user status, performs auto-registration
    or allows authentication bypass, returning the appropriate HTTP response.

    :param normalized_username: Normalized username.
    :param telegram_id: User ID in Telegram.
    :param is_bypass: Flag indicating whether authentication bypass is required.
    :return: HTTPResponse depending on user actions.
    """
    auto_reg_condition = Config.AUTO_REG_ENABLED and telegram_id is None
    if auto_reg_condition:
        logger.debug("Auto registration user: %s", normalized_username)
        await create_new_user(normalized_username, 0)
        telegram_id = 0
    bypass_condition = is_bypass or (Config.BYPASS_ENABLED and telegram_id == 0)
    if bypass_condition:
        logger.info("Authentication request bypassed by user %s",
                    normalized_username)
        return response_200()
    if telegram_id is None:
        logger.warning("User %s not found", normalized_username)
    else:
        logger.warning("2fa is not configured for user %s", normalized_username)
    return response_403()


# ==========BOT================
@router.message(Command(commands=['start']))
async def cmd_start(message: types.Message):
    """Authorization, database search and request sending"""
    user_telegram_id = message.from_user.id
    logger.info("%s request /start", user_telegram_id)
    start_message = (loc.MESSAGES["start"].format(user_telegram_id) + " " +
                     loc.MESSAGES["register_with_admin"])
    await answer_limited_message(message, start_message)


async def send_auth_request(telegram_id, domain_and_username):
    """Send an authorization confirmation request to the chat bot using the virtual keyboard."""
    normalized_username = domain_and_username.lower()
    current_time = time.time()
    if normalized_username in last_message_info:
        last_time, _, message_task = last_message_info[normalized_username]
        result = int(current_time - last_time)
        if result < Config.FREE2FA_TIMEOUT:
            # If the message was sent less than X seconds ago, skip sending a new one
            logger.info("%s %d Block new msg", normalized_username, result)
            return
    logger.info("Sending an authorization request for"
                "%s telegram id %s", normalized_username, telegram_id)
    markup = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=loc.MESSAGES["action_accept"],
                              callback_data=f"permit:{normalized_username}"),
         InlineKeyboardButton(text=loc.MESSAGES["action_reject"],
                              callback_data=f"reject:{normalized_username}")]
    ])

    # Sending a new message and saving the sending time
    try:
        sent_message = await send_limited_message(telegram_id, loc.MESSAGES["auth_request"], markup)
        message_task = asyncio.create_task(
            send_message_after_delay(
                telegram_id,
                Config.FREE2FA_TIMEOUT + 1,
                loc.MESSAGES["was_auth_request"].format(domain_and_username),
                normalized_username,
                sent_message.message_id
            )
        )
        logger.debug("last_message_info for %s", normalized_username)
        last_message_info[normalized_username] = (current_time,
                                                  sent_message.message_id, message_task)
    except aiogram_exceptions.TelegramBadRequest as req_err:
        logger.warning(
            "TelegramBadRequest while sending message to %s: %s", telegram_id, req_err)
    except aiogram_exceptions.TelegramNetworkError as network_err:
        logger.warning("Error when sending message: %s", network_err)
        if Config.ALLOW_API_FAILURE_PASS:
            auth_requests[normalized_username] = True
            logger.warning("Allow access [%s] by API failure ClientConnectorError",
                           normalized_username)


async def delete_message(chat_id, message_id):
    """Delete a user's Telegram message"""
    try:
        await delete_limited_message(chat_id, message_id)
    except aiogram_exceptions.TelegramBadRequest as req_err:
        logger.exception("TelegramBadRequest: %s", req_err)
    except aiogram_exceptions.AiogramError as other_err:
        logger.exception("Error in process_auth_response: %s", other_err)


async def send_message_after_delay(chat_id, delay, message_text, normalized_username, message_id):
    """Delete a user's Telegram message"""
    await asyncio.sleep(delay)
    try:
        await send_limited_message(chat_id, message_text)
        await delete_message(chat_id, message_id)
        auth_requests[normalized_username] = False
        asyncio.create_task(clear_auth_request(normalized_username))
    except aiogram_exceptions.AiogramError as error:
        logger.exception("Error when sending message after delay: %s", error)


@router.callback_query(lambda c: c.data.startswith("permit:") or c.data.startswith("reject:"))
async def process_auth_response(callback_query: types.CallbackQuery):
    """Handling the user's response to the request."""
    try:
        action, domain_and_username = callback_query.data.split(':')
        normalized_username = domain_and_username.lower()
        logger.debug("Response Processing for:"
                     "%s, action: %s", normalized_username, action)
        auth_requests[normalized_username] = (action == "permit")
        logger.debug(
            "State of auth_requests after response processing: %s", auth_requests)
        chat_id = callback_query.from_user.id
        message_id = callback_query.message.message_id
        await send_limited_edit_message(chat_id, message_id, None)
        if normalized_username in last_message_info:
            last_info = last_message_info[normalized_username]
            message_task = last_info[2]
            if message_task:
                message_task.cancel()
            if action == "reject":
                logger.debug("Action=reject:")
            if action == "permit":
                logger.debug("Action=permit:")
                await delete_message(callback_query.from_user.id, callback_query.message.message_id)
            last_message_info[normalized_username] = (time.time() -
                                                      Config.FREE2FA_TIMEOUT, last_info[1], None)
    except aiogram_exceptions.AiogramError as error:
        logger.exception("Error in process_auth_response: %s", error)


async def clear_auth_request(domain_and_username, delay=1):
    """Clearing the authorization of the request."""
    await asyncio.sleep(delay)
    if domain_and_username in auth_requests:
        del auth_requests[domain_and_username]
        logger.info("Authorization for %s cleared.", domain_and_username)


@app.get("/health")
async def health_check():
    """Server status"""
    return response_200()

# =======limits=============


async def send_limited_message(chat_id, text, reply_markup=None):
    """Method of sending a message"""
    await MessageLimiter.wait_for_message_slot()
    return await bot.send_message(chat_id, text, reply_markup=reply_markup)


async def answer_limited_message(message, text):
    """Method of sending a reply message"""
    await MessageLimiter.wait_for_message_slot()
    return await message.answer(text)


async def send_limited_edit_message(chat_id, message_id, reply_markup=None):
    """Method of message modification"""
    await MessageLimiter.wait_for_message_slot()
    return await bot.edit_message_reply_markup(chat_id, message_id, reply_markup=reply_markup)


async def delete_limited_message(chat_id, message_id):
    """Method for deleting a message"""
    await MessageLimiter.wait_for_message_slot()
    return await bot.delete_message(chat_id, message_id)

# =========================================================


async def start_aiogram():
    """Bot launch function"""
    while True:
        try:
            logger.info("Bot Launch...")
            await dp.start_polling(bot)
            logger.info("The bot has been successfully launched.")
            break  # Exit the loop after a successful start
        except aiogram_exceptions.TelegramNetworkError as network_err:
            logger.warning(f"Telegram network error: {network_err}")
        except aiogram_exceptions.AiogramError as other_err:
            logger.error(f"Unhandled exception: {other_err}")
        logger.warning("Retry in 5 seconds....")
        await asyncio.sleep(5)  # Delay before the next attempt


async def main():
    """Launch FastAPI and aiogram in one event loop"""
    asyncio.create_task(MessageLimiter.reset_message_count())
    loop = asyncio.get_event_loop()
    loop.create_task(start_aiogram())
    config = uvicorn.Config(
        app=app,
        host="0.0.0.0",
        port=5000,
        loop=loop,
        log_config=logging_config,
        ssl_keyfile='/app/certs/free2fa_api.key',
        ssl_certfile='/app/certs/free2fa_api.crt'
    )
    server = uvicorn.Server(config)
    await server.serve()

if __name__ == "__main__":
    asyncio.run(main())
