import functools
import json
from json import JSONDecodeError
from typing import List, Type

from pydantic import BaseModel
from requests import Response
from starlette.responses import JSONResponse


def is_positive_http_code(status_code: int) -> bool:
    # Expects a valid HTTP Code, does not check for correct types, only verifies correct ones
    first_digit = str(status_code)[0]
    return first_digit in [1, 2, 3]


def result_or_error(response_model: Type[BaseModel] = None, is_list: bool = False):
    def inner(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):

            def create_list(json: List[dict]):
                items = list()
                for entry in json:
                    items.append(response_model.parse_obj(entry))
                return items

            def create_object(json: dict):
                return response_model.parse_obj(json)

            result: Response = f(*args, **kwargs)

            if type(result) != Response:
                return result

            if result.status_code == 200:
                if response_model is None:
                    return result.json()
                if is_list:
                    return create_list(result.json())
                else:
                    return create_object(result.json())
            else:
                return JSONResponse(content=result.json(), status_code=result.status_code)

        return wrapper

    return inner


class ForwardedResponse:
    content: str
    status_code: int

    def __init__(self, content: str, status_code: int):
        self.status_code = status_code
        try:
            self.content = json.loads(content)
        except JSONDecodeError:
            self.content = content


def forward_response(f):
    def wrapper(*args, **kwargs):
        response: Response = f(*args, **kwargs)
        return ForwardedResponse(content=response.content.decode('utf-8'), status_code=response.status_code)

    return wrapper
