export class HttpError extends Error {
    constructor(message: string, public status: number, public data?: unknown) {
        super(message);
    }
}

export class NotFoundError extends HttpError {
    constructor(msg = "Not Found", data?: unknown) { super(msg, 404, data); }
}

export class ValidationError extends HttpError {
    constructor(msg = "Unprocessable Entity", data?: unknown) { super(msg, 422, data); }
}
