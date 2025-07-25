/******/ (() => { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ 7351:
/***/ (function(__unused_webpack_module, exports, __nccwpck_require__) {

"use strict";

var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.issue = exports.issueCommand = void 0;
const os = __importStar(__nccwpck_require__(2037));
const utils_1 = __nccwpck_require__(5278);
/**
 * Commands
 *
 * Command Format:
 *   ::name key=value,key=value::message
 *
 * Examples:
 *   ::warning::This is the message
 *   ::set-env name=MY_VAR::some value
 */
function issueCommand(command, properties, message) {
    const cmd = new Command(command, properties, message);
    process.stdout.write(cmd.toString() + os.EOL);
}
exports.issueCommand = issueCommand;
function issue(name, message = '') {
    issueCommand(name, {}, message);
}
exports.issue = issue;
const CMD_STRING = '::';
class Command {
    constructor(command, properties, message) {
        if (!command) {
            command = 'missing.command';
        }
        this.command = command;
        this.properties = properties;
        this.message = message;
    }
    toString() {
        let cmdStr = CMD_STRING + this.command;
        if (this.properties && Object.keys(this.properties).length > 0) {
            cmdStr += ' ';
            let first = true;
            for (const key in this.properties) {
                if (this.properties.hasOwnProperty(key)) {
                    const val = this.properties[key];
                    if (val) {
                        if (first) {
                            first = false;
                        }
                        else {
                            cmdStr += ',';
                        }
                        cmdStr += `${key}=${escapeProperty(val)}`;
                    }
                }
            }
        }
        cmdStr += `${CMD_STRING}${escapeData(this.message)}`;
        return cmdStr;
    }
}
function escapeData(s) {
    return utils_1.toCommandValue(s)
        .replace(/%/g, '%25')
        .replace(/\r/g, '%0D')
        .replace(/\n/g, '%0A');
}
function escapeProperty(s) {
    return utils_1.toCommandValue(s)
        .replace(/%/g, '%25')
        .replace(/\r/g, '%0D')
        .replace(/\n/g, '%0A')
        .replace(/:/g, '%3A')
        .replace(/,/g, '%2C');
}
//# sourceMappingURL=command.js.map

/***/ }),

/***/ 2186:
/***/ (function(__unused_webpack_module, exports, __nccwpck_require__) {

"use strict";

var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.getIDToken = exports.getState = exports.saveState = exports.group = exports.endGroup = exports.startGroup = exports.info = exports.notice = exports.warning = exports.error = exports.debug = exports.isDebug = exports.setFailed = exports.setCommandEcho = exports.setOutput = exports.getBooleanInput = exports.getMultilineInput = exports.getInput = exports.addPath = exports.setSecret = exports.exportVariable = exports.ExitCode = void 0;
const command_1 = __nccwpck_require__(7351);
const file_command_1 = __nccwpck_require__(717);
const utils_1 = __nccwpck_require__(5278);
const os = __importStar(__nccwpck_require__(2037));
const path = __importStar(__nccwpck_require__(1017));
const oidc_utils_1 = __nccwpck_require__(8041);
/**
 * The code to exit an action
 */
var ExitCode;
(function (ExitCode) {
    /**
     * A code indicating that the action was successful
     */
    ExitCode[ExitCode["Success"] = 0] = "Success";
    /**
     * A code indicating that the action was a failure
     */
    ExitCode[ExitCode["Failure"] = 1] = "Failure";
})(ExitCode = exports.ExitCode || (exports.ExitCode = {}));
//-----------------------------------------------------------------------
// Variables
//-----------------------------------------------------------------------
/**
 * Sets env variable for this action and future actions in the job
 * @param name the name of the variable to set
 * @param val the value of the variable. Non-string values will be converted to a string via JSON.stringify
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function exportVariable(name, val) {
    const convertedVal = utils_1.toCommandValue(val);
    process.env[name] = convertedVal;
    const filePath = process.env['GITHUB_ENV'] || '';
    if (filePath) {
        return file_command_1.issueFileCommand('ENV', file_command_1.prepareKeyValueMessage(name, val));
    }
    command_1.issueCommand('set-env', { name }, convertedVal);
}
exports.exportVariable = exportVariable;
/**
 * Registers a secret which will get masked from logs
 * @param secret value of the secret
 */
function setSecret(secret) {
    command_1.issueCommand('add-mask', {}, secret);
}
exports.setSecret = setSecret;
/**
 * Prepends inputPath to the PATH (for this action and future actions)
 * @param inputPath
 */
function addPath(inputPath) {
    const filePath = process.env['GITHUB_PATH'] || '';
    if (filePath) {
        file_command_1.issueFileCommand('PATH', inputPath);
    }
    else {
        command_1.issueCommand('add-path', {}, inputPath);
    }
    process.env['PATH'] = `${inputPath}${path.delimiter}${process.env['PATH']}`;
}
exports.addPath = addPath;
/**
 * Gets the value of an input.
 * Unless trimWhitespace is set to false in InputOptions, the value is also trimmed.
 * Returns an empty string if the value is not defined.
 *
 * @param     name     name of the input to get
 * @param     options  optional. See InputOptions.
 * @returns   string
 */
function getInput(name, options) {
    const val = process.env[`INPUT_${name.replace(/ /g, '_').toUpperCase()}`] || '';
    if (options && options.required && !val) {
        throw new Error(`Input required and not supplied: ${name}`);
    }
    if (options && options.trimWhitespace === false) {
        return val;
    }
    return val.trim();
}
exports.getInput = getInput;
/**
 * Gets the values of an multiline input.  Each value is also trimmed.
 *
 * @param     name     name of the input to get
 * @param     options  optional. See InputOptions.
 * @returns   string[]
 *
 */
function getMultilineInput(name, options) {
    const inputs = getInput(name, options)
        .split('\n')
        .filter(x => x !== '');
    if (options && options.trimWhitespace === false) {
        return inputs;
    }
    return inputs.map(input => input.trim());
}
exports.getMultilineInput = getMultilineInput;
/**
 * Gets the input value of the boolean type in the YAML 1.2 "core schema" specification.
 * Support boolean input list: `true | True | TRUE | false | False | FALSE` .
 * The return value is also in boolean type.
 * ref: https://yaml.org/spec/1.2/spec.html#id2804923
 *
 * @param     name     name of the input to get
 * @param     options  optional. See InputOptions.
 * @returns   boolean
 */
function getBooleanInput(name, options) {
    const trueValue = ['true', 'True', 'TRUE'];
    const falseValue = ['false', 'False', 'FALSE'];
    const val = getInput(name, options);
    if (trueValue.includes(val))
        return true;
    if (falseValue.includes(val))
        return false;
    throw new TypeError(`Input does not meet YAML 1.2 "Core Schema" specification: ${name}\n` +
        `Support boolean input list: \`true | True | TRUE | false | False | FALSE\``);
}
exports.getBooleanInput = getBooleanInput;
/**
 * Sets the value of an output.
 *
 * @param     name     name of the output to set
 * @param     value    value to store. Non-string values will be converted to a string via JSON.stringify
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function setOutput(name, value) {
    const filePath = process.env['GITHUB_OUTPUT'] || '';
    if (filePath) {
        return file_command_1.issueFileCommand('OUTPUT', file_command_1.prepareKeyValueMessage(name, value));
    }
    process.stdout.write(os.EOL);
    command_1.issueCommand('set-output', { name }, utils_1.toCommandValue(value));
}
exports.setOutput = setOutput;
/**
 * Enables or disables the echoing of commands into stdout for the rest of the step.
 * Echoing is disabled by default if ACTIONS_STEP_DEBUG is not set.
 *
 */
function setCommandEcho(enabled) {
    command_1.issue('echo', enabled ? 'on' : 'off');
}
exports.setCommandEcho = setCommandEcho;
//-----------------------------------------------------------------------
// Results
//-----------------------------------------------------------------------
/**
 * Sets the action status to failed.
 * When the action exits it will be with an exit code of 1
 * @param message add error issue message
 */
function setFailed(message) {
    process.exitCode = ExitCode.Failure;
    error(message);
}
exports.setFailed = setFailed;
//-----------------------------------------------------------------------
// Logging Commands
//-----------------------------------------------------------------------
/**
 * Gets whether Actions Step Debug is on or not
 */
function isDebug() {
    return process.env['RUNNER_DEBUG'] === '1';
}
exports.isDebug = isDebug;
/**
 * Writes debug message to user log
 * @param message debug message
 */
function debug(message) {
    command_1.issueCommand('debug', {}, message);
}
exports.debug = debug;
/**
 * Adds an error issue
 * @param message error issue message. Errors will be converted to string via toString()
 * @param properties optional properties to add to the annotation.
 */
function error(message, properties = {}) {
    command_1.issueCommand('error', utils_1.toCommandProperties(properties), message instanceof Error ? message.toString() : message);
}
exports.error = error;
/**
 * Adds a warning issue
 * @param message warning issue message. Errors will be converted to string via toString()
 * @param properties optional properties to add to the annotation.
 */
function warning(message, properties = {}) {
    command_1.issueCommand('warning', utils_1.toCommandProperties(properties), message instanceof Error ? message.toString() : message);
}
exports.warning = warning;
/**
 * Adds a notice issue
 * @param message notice issue message. Errors will be converted to string via toString()
 * @param properties optional properties to add to the annotation.
 */
function notice(message, properties = {}) {
    command_1.issueCommand('notice', utils_1.toCommandProperties(properties), message instanceof Error ? message.toString() : message);
}
exports.notice = notice;
/**
 * Writes info to log with console.log.
 * @param message info message
 */
function info(message) {
    process.stdout.write(message + os.EOL);
}
exports.info = info;
/**
 * Begin an output group.
 *
 * Output until the next `groupEnd` will be foldable in this group
 *
 * @param name The name of the output group
 */
function startGroup(name) {
    command_1.issue('group', name);
}
exports.startGroup = startGroup;
/**
 * End an output group.
 */
function endGroup() {
    command_1.issue('endgroup');
}
exports.endGroup = endGroup;
/**
 * Wrap an asynchronous function call in a group.
 *
 * Returns the same type as the function itself.
 *
 * @param name The name of the group
 * @param fn The function to wrap in the group
 */
function group(name, fn) {
    return __awaiter(this, void 0, void 0, function* () {
        startGroup(name);
        let result;
        try {
            result = yield fn();
        }
        finally {
            endGroup();
        }
        return result;
    });
}
exports.group = group;
//-----------------------------------------------------------------------
// Wrapper action state
//-----------------------------------------------------------------------
/**
 * Saves state for current action, the state can only be retrieved by this action's post job execution.
 *
 * @param     name     name of the state to store
 * @param     value    value to store. Non-string values will be converted to a string via JSON.stringify
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function saveState(name, value) {
    const filePath = process.env['GITHUB_STATE'] || '';
    if (filePath) {
        return file_command_1.issueFileCommand('STATE', file_command_1.prepareKeyValueMessage(name, value));
    }
    command_1.issueCommand('save-state', { name }, utils_1.toCommandValue(value));
}
exports.saveState = saveState;
/**
 * Gets the value of an state set by this action's main execution.
 *
 * @param     name     name of the state to get
 * @returns   string
 */
function getState(name) {
    return process.env[`STATE_${name}`] || '';
}
exports.getState = getState;
function getIDToken(aud) {
    return __awaiter(this, void 0, void 0, function* () {
        return yield oidc_utils_1.OidcClient.getIDToken(aud);
    });
}
exports.getIDToken = getIDToken;
/**
 * Summary exports
 */
var summary_1 = __nccwpck_require__(1327);
Object.defineProperty(exports, "summary", ({ enumerable: true, get: function () { return summary_1.summary; } }));
/**
 * @deprecated use core.summary
 */
var summary_2 = __nccwpck_require__(1327);
Object.defineProperty(exports, "markdownSummary", ({ enumerable: true, get: function () { return summary_2.markdownSummary; } }));
/**
 * Path exports
 */
var path_utils_1 = __nccwpck_require__(2981);
Object.defineProperty(exports, "toPosixPath", ({ enumerable: true, get: function () { return path_utils_1.toPosixPath; } }));
Object.defineProperty(exports, "toWin32Path", ({ enumerable: true, get: function () { return path_utils_1.toWin32Path; } }));
Object.defineProperty(exports, "toPlatformPath", ({ enumerable: true, get: function () { return path_utils_1.toPlatformPath; } }));
//# sourceMappingURL=core.js.map

/***/ }),

/***/ 717:
/***/ (function(__unused_webpack_module, exports, __nccwpck_require__) {

"use strict";

// For internal use, subject to change.
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.prepareKeyValueMessage = exports.issueFileCommand = void 0;
// We use any as a valid input type
/* eslint-disable @typescript-eslint/no-explicit-any */
const fs = __importStar(__nccwpck_require__(7147));
const os = __importStar(__nccwpck_require__(2037));
const uuid_1 = __nccwpck_require__(5840);
const utils_1 = __nccwpck_require__(5278);
function issueFileCommand(command, message) {
    const filePath = process.env[`GITHUB_${command}`];
    if (!filePath) {
        throw new Error(`Unable to find environment variable for file command ${command}`);
    }
    if (!fs.existsSync(filePath)) {
        throw new Error(`Missing file at path: ${filePath}`);
    }
    fs.appendFileSync(filePath, `${utils_1.toCommandValue(message)}${os.EOL}`, {
        encoding: 'utf8'
    });
}
exports.issueFileCommand = issueFileCommand;
function prepareKeyValueMessage(key, value) {
    const delimiter = `ghadelimiter_${uuid_1.v4()}`;
    const convertedValue = utils_1.toCommandValue(value);
    // These should realistically never happen, but just in case someone finds a
    // way to exploit uuid generation let's not allow keys or values that contain
    // the delimiter.
    if (key.includes(delimiter)) {
        throw new Error(`Unexpected input: name should not contain the delimiter "${delimiter}"`);
    }
    if (convertedValue.includes(delimiter)) {
        throw new Error(`Unexpected input: value should not contain the delimiter "${delimiter}"`);
    }
    return `${key}<<${delimiter}${os.EOL}${convertedValue}${os.EOL}${delimiter}`;
}
exports.prepareKeyValueMessage = prepareKeyValueMessage;
//# sourceMappingURL=file-command.js.map

/***/ }),

/***/ 8041:
/***/ (function(__unused_webpack_module, exports, __nccwpck_require__) {

"use strict";

var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.OidcClient = void 0;
const http_client_1 = __nccwpck_require__(6255);
const auth_1 = __nccwpck_require__(5526);
const core_1 = __nccwpck_require__(2186);
class OidcClient {
    static createHttpClient(allowRetry = true, maxRetry = 10) {
        const requestOptions = {
            allowRetries: allowRetry,
            maxRetries: maxRetry
        };
        return new http_client_1.HttpClient('actions/oidc-client', [new auth_1.BearerCredentialHandler(OidcClient.getRequestToken())], requestOptions);
    }
    static getRequestToken() {
        const token = process.env['ACTIONS_ID_TOKEN_REQUEST_TOKEN'];
        if (!token) {
            throw new Error('Unable to get ACTIONS_ID_TOKEN_REQUEST_TOKEN env variable');
        }
        return token;
    }
    static getIDTokenUrl() {
        const runtimeUrl = process.env['ACTIONS_ID_TOKEN_REQUEST_URL'];
        if (!runtimeUrl) {
            throw new Error('Unable to get ACTIONS_ID_TOKEN_REQUEST_URL env variable');
        }
        return runtimeUrl;
    }
    static getCall(id_token_url) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            const httpclient = OidcClient.createHttpClient();
            const res = yield httpclient
                .getJson(id_token_url)
                .catch(error => {
                throw new Error(`Failed to get ID Token. \n 
        Error Code : ${error.statusCode}\n 
        Error Message: ${error.result.message}`);
            });
            const id_token = (_a = res.result) === null || _a === void 0 ? void 0 : _a.value;
            if (!id_token) {
                throw new Error('Response json body do not have ID Token field');
            }
            return id_token;
        });
    }
    static getIDToken(audience) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                // New ID Token is requested from action service
                let id_token_url = OidcClient.getIDTokenUrl();
                if (audience) {
                    const encodedAudience = encodeURIComponent(audience);
                    id_token_url = `${id_token_url}&audience=${encodedAudience}`;
                }
                core_1.debug(`ID token url is ${id_token_url}`);
                const id_token = yield OidcClient.getCall(id_token_url);
                core_1.setSecret(id_token);
                return id_token;
            }
            catch (error) {
                throw new Error(`Error message: ${error.message}`);
            }
        });
    }
}
exports.OidcClient = OidcClient;
//# sourceMappingURL=oidc-utils.js.map

/***/ }),

/***/ 2981:
/***/ (function(__unused_webpack_module, exports, __nccwpck_require__) {

"use strict";

var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.toPlatformPath = exports.toWin32Path = exports.toPosixPath = void 0;
const path = __importStar(__nccwpck_require__(1017));
/**
 * toPosixPath converts the given path to the posix form. On Windows, \\ will be
 * replaced with /.
 *
 * @param pth. Path to transform.
 * @return string Posix path.
 */
function toPosixPath(pth) {
    return pth.replace(/[\\]/g, '/');
}
exports.toPosixPath = toPosixPath;
/**
 * toWin32Path converts the given path to the win32 form. On Linux, / will be
 * replaced with \\.
 *
 * @param pth. Path to transform.
 * @return string Win32 path.
 */
function toWin32Path(pth) {
    return pth.replace(/[/]/g, '\\');
}
exports.toWin32Path = toWin32Path;
/**
 * toPlatformPath converts the given path to a platform-specific path. It does
 * this by replacing instances of / and \ with the platform-specific path
 * separator.
 *
 * @param pth The path to platformize.
 * @return string The platform-specific path.
 */
function toPlatformPath(pth) {
    return pth.replace(/[/\\]/g, path.sep);
}
exports.toPlatformPath = toPlatformPath;
//# sourceMappingURL=path-utils.js.map

/***/ }),

/***/ 1327:
/***/ (function(__unused_webpack_module, exports, __nccwpck_require__) {

"use strict";

var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.summary = exports.markdownSummary = exports.SUMMARY_DOCS_URL = exports.SUMMARY_ENV_VAR = void 0;
const os_1 = __nccwpck_require__(2037);
const fs_1 = __nccwpck_require__(7147);
const { access, appendFile, writeFile } = fs_1.promises;
exports.SUMMARY_ENV_VAR = 'GITHUB_STEP_SUMMARY';
exports.SUMMARY_DOCS_URL = 'https://docs.github.com/actions/using-workflows/workflow-commands-for-github-actions#adding-a-job-summary';
class Summary {
    constructor() {
        this._buffer = '';
    }
    /**
     * Finds the summary file path from the environment, rejects if env var is not found or file does not exist
     * Also checks r/w permissions.
     *
     * @returns step summary file path
     */
    filePath() {
        return __awaiter(this, void 0, void 0, function* () {
            if (this._filePath) {
                return this._filePath;
            }
            const pathFromEnv = process.env[exports.SUMMARY_ENV_VAR];
            if (!pathFromEnv) {
                throw new Error(`Unable to find environment variable for $${exports.SUMMARY_ENV_VAR}. Check if your runtime environment supports job summaries.`);
            }
            try {
                yield access(pathFromEnv, fs_1.constants.R_OK | fs_1.constants.W_OK);
            }
            catch (_a) {
                throw new Error(`Unable to access summary file: '${pathFromEnv}'. Check if the file has correct read/write permissions.`);
            }
            this._filePath = pathFromEnv;
            return this._filePath;
        });
    }
    /**
     * Wraps content in an HTML tag, adding any HTML attributes
     *
     * @param {string} tag HTML tag to wrap
     * @param {string | null} content content within the tag
     * @param {[attribute: string]: string} attrs key-value list of HTML attributes to add
     *
     * @returns {string} content wrapped in HTML element
     */
    wrap(tag, content, attrs = {}) {
        const htmlAttrs = Object.entries(attrs)
            .map(([key, value]) => ` ${key}="${value}"`)
            .join('');
        if (!content) {
            return `<${tag}${htmlAttrs}>`;
        }
        return `<${tag}${htmlAttrs}>${content}</${tag}>`;
    }
    /**
     * Writes text in the buffer to the summary buffer file and empties buffer. Will append by default.
     *
     * @param {SummaryWriteOptions} [options] (optional) options for write operation
     *
     * @returns {Promise<Summary>} summary instance
     */
    write(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const overwrite = !!(options === null || options === void 0 ? void 0 : options.overwrite);
            const filePath = yield this.filePath();
            const writeFunc = overwrite ? writeFile : appendFile;
            yield writeFunc(filePath, this._buffer, { encoding: 'utf8' });
            return this.emptyBuffer();
        });
    }
    /**
     * Clears the summary buffer and wipes the summary file
     *
     * @returns {Summary} summary instance
     */
    clear() {
        return __awaiter(this, void 0, void 0, function* () {
            return this.emptyBuffer().write({ overwrite: true });
        });
    }
    /**
     * Returns the current summary buffer as a string
     *
     * @returns {string} string of summary buffer
     */
    stringify() {
        return this._buffer;
    }
    /**
     * If the summary buffer is empty
     *
     * @returns {boolen} true if the buffer is empty
     */
    isEmptyBuffer() {
        return this._buffer.length === 0;
    }
    /**
     * Resets the summary buffer without writing to summary file
     *
     * @returns {Summary} summary instance
     */
    emptyBuffer() {
        this._buffer = '';
        return this;
    }
    /**
     * Adds raw text to the summary buffer
     *
     * @param {string} text content to add
     * @param {boolean} [addEOL=false] (optional) append an EOL to the raw text (default: false)
     *
     * @returns {Summary} summary instance
     */
    addRaw(text, addEOL = false) {
        this._buffer += text;
        return addEOL ? this.addEOL() : this;
    }
    /**
     * Adds the operating system-specific end-of-line marker to the buffer
     *
     * @returns {Summary} summary instance
     */
    addEOL() {
        return this.addRaw(os_1.EOL);
    }
    /**
     * Adds an HTML codeblock to the summary buffer
     *
     * @param {string} code content to render within fenced code block
     * @param {string} lang (optional) language to syntax highlight code
     *
     * @returns {Summary} summary instance
     */
    addCodeBlock(code, lang) {
        const attrs = Object.assign({}, (lang && { lang }));
        const element = this.wrap('pre', this.wrap('code', code), attrs);
        return this.addRaw(element).addEOL();
    }
    /**
     * Adds an HTML list to the summary buffer
     *
     * @param {string[]} items list of items to render
     * @param {boolean} [ordered=false] (optional) if the rendered list should be ordered or not (default: false)
     *
     * @returns {Summary} summary instance
     */
    addList(items, ordered = false) {
        const tag = ordered ? 'ol' : 'ul';
        const listItems = items.map(item => this.wrap('li', item)).join('');
        const element = this.wrap(tag, listItems);
        return this.addRaw(element).addEOL();
    }
    /**
     * Adds an HTML table to the summary buffer
     *
     * @param {SummaryTableCell[]} rows table rows
     *
     * @returns {Summary} summary instance
     */
    addTable(rows) {
        const tableBody = rows
            .map(row => {
            const cells = row
                .map(cell => {
                if (typeof cell === 'string') {
                    return this.wrap('td', cell);
                }
                const { header, data, colspan, rowspan } = cell;
                const tag = header ? 'th' : 'td';
                const attrs = Object.assign(Object.assign({}, (colspan && { colspan })), (rowspan && { rowspan }));
                return this.wrap(tag, data, attrs);
            })
                .join('');
            return this.wrap('tr', cells);
        })
            .join('');
        const element = this.wrap('table', tableBody);
        return this.addRaw(element).addEOL();
    }
    /**
     * Adds a collapsable HTML details element to the summary buffer
     *
     * @param {string} label text for the closed state
     * @param {string} content collapsable content
     *
     * @returns {Summary} summary instance
     */
    addDetails(label, content) {
        const element = this.wrap('details', this.wrap('summary', label) + content);
        return this.addRaw(element).addEOL();
    }
    /**
     * Adds an HTML image tag to the summary buffer
     *
     * @param {string} src path to the image you to embed
     * @param {string} alt text description of the image
     * @param {SummaryImageOptions} options (optional) addition image attributes
     *
     * @returns {Summary} summary instance
     */
    addImage(src, alt, options) {
        const { width, height } = options || {};
        const attrs = Object.assign(Object.assign({}, (width && { width })), (height && { height }));
        const element = this.wrap('img', null, Object.assign({ src, alt }, attrs));
        return this.addRaw(element).addEOL();
    }
    /**
     * Adds an HTML section heading element
     *
     * @param {string} text heading text
     * @param {number | string} [level=1] (optional) the heading level, default: 1
     *
     * @returns {Summary} summary instance
     */
    addHeading(text, level) {
        const tag = `h${level}`;
        const allowedTag = ['h1', 'h2', 'h3', 'h4', 'h5', 'h6'].includes(tag)
            ? tag
            : 'h1';
        const element = this.wrap(allowedTag, text);
        return this.addRaw(element).addEOL();
    }
    /**
     * Adds an HTML thematic break (<hr>) to the summary buffer
     *
     * @returns {Summary} summary instance
     */
    addSeparator() {
        const element = this.wrap('hr', null);
        return this.addRaw(element).addEOL();
    }
    /**
     * Adds an HTML line break (<br>) to the summary buffer
     *
     * @returns {Summary} summary instance
     */
    addBreak() {
        const element = this.wrap('br', null);
        return this.addRaw(element).addEOL();
    }
    /**
     * Adds an HTML blockquote to the summary buffer
     *
     * @param {string} text quote text
     * @param {string} cite (optional) citation url
     *
     * @returns {Summary} summary instance
     */
    addQuote(text, cite) {
        const attrs = Object.assign({}, (cite && { cite }));
        const element = this.wrap('blockquote', text, attrs);
        return this.addRaw(element).addEOL();
    }
    /**
     * Adds an HTML anchor tag to the summary buffer
     *
     * @param {string} text link text/content
     * @param {string} href hyperlink
     *
     * @returns {Summary} summary instance
     */
    addLink(text, href) {
        const element = this.wrap('a', text, { href });
        return this.addRaw(element).addEOL();
    }
}
const _summary = new Summary();
/**
 * @deprecated use `core.summary`
 */
exports.markdownSummary = _summary;
exports.summary = _summary;
//# sourceMappingURL=summary.js.map

/***/ }),

/***/ 5278:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

// We use any as a valid input type
/* eslint-disable @typescript-eslint/no-explicit-any */
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.toCommandProperties = exports.toCommandValue = void 0;
/**
 * Sanitizes an input into a string so it can be passed into issueCommand safely
 * @param input input to sanitize into a string
 */
function toCommandValue(input) {
    if (input === null || input === undefined) {
        return '';
    }
    else if (typeof input === 'string' || input instanceof String) {
        return input;
    }
    return JSON.stringify(input);
}
exports.toCommandValue = toCommandValue;
/**
 *
 * @param annotationProperties
 * @returns The command properties to send with the actual annotation command
 * See IssueCommandProperties: https://github.com/actions/runner/blob/main/src/Runner.Worker/ActionCommandManager.cs#L646
 */
function toCommandProperties(annotationProperties) {
    if (!Object.keys(annotationProperties).length) {
        return {};
    }
    return {
        title: annotationProperties.title,
        file: annotationProperties.file,
        line: annotationProperties.startLine,
        endLine: annotationProperties.endLine,
        col: annotationProperties.startColumn,
        endColumn: annotationProperties.endColumn
    };
}
exports.toCommandProperties = toCommandProperties;
//# sourceMappingURL=utils.js.map

/***/ }),

/***/ 5526:
/***/ (function(__unused_webpack_module, exports) {

"use strict";

var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.PersonalAccessTokenCredentialHandler = exports.BearerCredentialHandler = exports.BasicCredentialHandler = void 0;
class BasicCredentialHandler {
    constructor(username, password) {
        this.username = username;
        this.password = password;
    }
    prepareRequest(options) {
        if (!options.headers) {
            throw Error('The request has no headers');
        }
        options.headers['Authorization'] = `Basic ${Buffer.from(`${this.username}:${this.password}`).toString('base64')}`;
    }
    // This handler cannot handle 401
    canHandleAuthentication() {
        return false;
    }
    handleAuthentication() {
        return __awaiter(this, void 0, void 0, function* () {
            throw new Error('not implemented');
        });
    }
}
exports.BasicCredentialHandler = BasicCredentialHandler;
class BearerCredentialHandler {
    constructor(token) {
        this.token = token;
    }
    // currently implements pre-authorization
    // TODO: support preAuth = false where it hooks on 401
    prepareRequest(options) {
        if (!options.headers) {
            throw Error('The request has no headers');
        }
        options.headers['Authorization'] = `Bearer ${this.token}`;
    }
    // This handler cannot handle 401
    canHandleAuthentication() {
        return false;
    }
    handleAuthentication() {
        return __awaiter(this, void 0, void 0, function* () {
            throw new Error('not implemented');
        });
    }
}
exports.BearerCredentialHandler = BearerCredentialHandler;
class PersonalAccessTokenCredentialHandler {
    constructor(token) {
        this.token = token;
    }
    // currently implements pre-authorization
    // TODO: support preAuth = false where it hooks on 401
    prepareRequest(options) {
        if (!options.headers) {
            throw Error('The request has no headers');
        }
        options.headers['Authorization'] = `Basic ${Buffer.from(`PAT:${this.token}`).toString('base64')}`;
    }
    // This handler cannot handle 401
    canHandleAuthentication() {
        return false;
    }
    handleAuthentication() {
        return __awaiter(this, void 0, void 0, function* () {
            throw new Error('not implemented');
        });
    }
}
exports.PersonalAccessTokenCredentialHandler = PersonalAccessTokenCredentialHandler;
//# sourceMappingURL=auth.js.map

/***/ }),

/***/ 6255:
/***/ (function(__unused_webpack_module, exports, __nccwpck_require__) {

"use strict";

/* eslint-disable @typescript-eslint/no-explicit-any */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.HttpClient = exports.isHttps = exports.HttpClientResponse = exports.HttpClientError = exports.getProxyUrl = exports.MediaTypes = exports.Headers = exports.HttpCodes = void 0;
const http = __importStar(__nccwpck_require__(3685));
const https = __importStar(__nccwpck_require__(5687));
const pm = __importStar(__nccwpck_require__(9835));
const tunnel = __importStar(__nccwpck_require__(4294));
var HttpCodes;
(function (HttpCodes) {
    HttpCodes[HttpCodes["OK"] = 200] = "OK";
    HttpCodes[HttpCodes["MultipleChoices"] = 300] = "MultipleChoices";
    HttpCodes[HttpCodes["MovedPermanently"] = 301] = "MovedPermanently";
    HttpCodes[HttpCodes["ResourceMoved"] = 302] = "ResourceMoved";
    HttpCodes[HttpCodes["SeeOther"] = 303] = "SeeOther";
    HttpCodes[HttpCodes["NotModified"] = 304] = "NotModified";
    HttpCodes[HttpCodes["UseProxy"] = 305] = "UseProxy";
    HttpCodes[HttpCodes["SwitchProxy"] = 306] = "SwitchProxy";
    HttpCodes[HttpCodes["TemporaryRedirect"] = 307] = "TemporaryRedirect";
    HttpCodes[HttpCodes["PermanentRedirect"] = 308] = "PermanentRedirect";
    HttpCodes[HttpCodes["BadRequest"] = 400] = "BadRequest";
    HttpCodes[HttpCodes["Unauthorized"] = 401] = "Unauthorized";
    HttpCodes[HttpCodes["PaymentRequired"] = 402] = "PaymentRequired";
    HttpCodes[HttpCodes["Forbidden"] = 403] = "Forbidden";
    HttpCodes[HttpCodes["NotFound"] = 404] = "NotFound";
    HttpCodes[HttpCodes["MethodNotAllowed"] = 405] = "MethodNotAllowed";
    HttpCodes[HttpCodes["NotAcceptable"] = 406] = "NotAcceptable";
    HttpCodes[HttpCodes["ProxyAuthenticationRequired"] = 407] = "ProxyAuthenticationRequired";
    HttpCodes[HttpCodes["RequestTimeout"] = 408] = "RequestTimeout";
    HttpCodes[HttpCodes["Conflict"] = 409] = "Conflict";
    HttpCodes[HttpCodes["Gone"] = 410] = "Gone";
    HttpCodes[HttpCodes["TooManyRequests"] = 429] = "TooManyRequests";
    HttpCodes[HttpCodes["InternalServerError"] = 500] = "InternalServerError";
    HttpCodes[HttpCodes["NotImplemented"] = 501] = "NotImplemented";
    HttpCodes[HttpCodes["BadGateway"] = 502] = "BadGateway";
    HttpCodes[HttpCodes["ServiceUnavailable"] = 503] = "ServiceUnavailable";
    HttpCodes[HttpCodes["GatewayTimeout"] = 504] = "GatewayTimeout";
})(HttpCodes = exports.HttpCodes || (exports.HttpCodes = {}));
var Headers;
(function (Headers) {
    Headers["Accept"] = "accept";
    Headers["ContentType"] = "content-type";
})(Headers = exports.Headers || (exports.Headers = {}));
var MediaTypes;
(function (MediaTypes) {
    MediaTypes["ApplicationJson"] = "application/json";
})(MediaTypes = exports.MediaTypes || (exports.MediaTypes = {}));
/**
 * Returns the proxy URL, depending upon the supplied url and proxy environment variables.
 * @param serverUrl  The server URL where the request will be sent. For example, https://api.github.com
 */
function getProxyUrl(serverUrl) {
    const proxyUrl = pm.getProxyUrl(new URL(serverUrl));
    return proxyUrl ? proxyUrl.href : '';
}
exports.getProxyUrl = getProxyUrl;
const HttpRedirectCodes = [
    HttpCodes.MovedPermanently,
    HttpCodes.ResourceMoved,
    HttpCodes.SeeOther,
    HttpCodes.TemporaryRedirect,
    HttpCodes.PermanentRedirect
];
const HttpResponseRetryCodes = [
    HttpCodes.BadGateway,
    HttpCodes.ServiceUnavailable,
    HttpCodes.GatewayTimeout
];
const RetryableHttpVerbs = ['OPTIONS', 'GET', 'DELETE', 'HEAD'];
const ExponentialBackoffCeiling = 10;
const ExponentialBackoffTimeSlice = 5;
class HttpClientError extends Error {
    constructor(message, statusCode) {
        super(message);
        this.name = 'HttpClientError';
        this.statusCode = statusCode;
        Object.setPrototypeOf(this, HttpClientError.prototype);
    }
}
exports.HttpClientError = HttpClientError;
class HttpClientResponse {
    constructor(message) {
        this.message = message;
    }
    readBody() {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve) => __awaiter(this, void 0, void 0, function* () {
                let output = Buffer.alloc(0);
                this.message.on('data', (chunk) => {
                    output = Buffer.concat([output, chunk]);
                });
                this.message.on('end', () => {
                    resolve(output.toString());
                });
            }));
        });
    }
    readBodyBuffer() {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve) => __awaiter(this, void 0, void 0, function* () {
                const chunks = [];
                this.message.on('data', (chunk) => {
                    chunks.push(chunk);
                });
                this.message.on('end', () => {
                    resolve(Buffer.concat(chunks));
                });
            }));
        });
    }
}
exports.HttpClientResponse = HttpClientResponse;
function isHttps(requestUrl) {
    const parsedUrl = new URL(requestUrl);
    return parsedUrl.protocol === 'https:';
}
exports.isHttps = isHttps;
class HttpClient {
    constructor(userAgent, handlers, requestOptions) {
        this._ignoreSslError = false;
        this._allowRedirects = true;
        this._allowRedirectDowngrade = false;
        this._maxRedirects = 50;
        this._allowRetries = false;
        this._maxRetries = 1;
        this._keepAlive = false;
        this._disposed = false;
        this.userAgent = userAgent;
        this.handlers = handlers || [];
        this.requestOptions = requestOptions;
        if (requestOptions) {
            if (requestOptions.ignoreSslError != null) {
                this._ignoreSslError = requestOptions.ignoreSslError;
            }
            this._socketTimeout = requestOptions.socketTimeout;
            if (requestOptions.allowRedirects != null) {
                this._allowRedirects = requestOptions.allowRedirects;
            }
            if (requestOptions.allowRedirectDowngrade != null) {
                this._allowRedirectDowngrade = requestOptions.allowRedirectDowngrade;
            }
            if (requestOptions.maxRedirects != null) {
                this._maxRedirects = Math.max(requestOptions.maxRedirects, 0);
            }
            if (requestOptions.keepAlive != null) {
                this._keepAlive = requestOptions.keepAlive;
            }
            if (requestOptions.allowRetries != null) {
                this._allowRetries = requestOptions.allowRetries;
            }
            if (requestOptions.maxRetries != null) {
                this._maxRetries = requestOptions.maxRetries;
            }
        }
    }
    options(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request('OPTIONS', requestUrl, null, additionalHeaders || {});
        });
    }
    get(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request('GET', requestUrl, null, additionalHeaders || {});
        });
    }
    del(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request('DELETE', requestUrl, null, additionalHeaders || {});
        });
    }
    post(requestUrl, data, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request('POST', requestUrl, data, additionalHeaders || {});
        });
    }
    patch(requestUrl, data, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request('PATCH', requestUrl, data, additionalHeaders || {});
        });
    }
    put(requestUrl, data, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request('PUT', requestUrl, data, additionalHeaders || {});
        });
    }
    head(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request('HEAD', requestUrl, null, additionalHeaders || {});
        });
    }
    sendStream(verb, requestUrl, stream, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request(verb, requestUrl, stream, additionalHeaders);
        });
    }
    /**
     * Gets a typed object from an endpoint
     * Be aware that not found returns a null.  Other errors (4xx, 5xx) reject the promise
     */
    getJson(requestUrl, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
            const res = yield this.get(requestUrl, additionalHeaders);
            return this._processResponse(res, this.requestOptions);
        });
    }
    postJson(requestUrl, obj, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            const data = JSON.stringify(obj, null, 2);
            additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
            additionalHeaders[Headers.ContentType] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.ContentType, MediaTypes.ApplicationJson);
            const res = yield this.post(requestUrl, data, additionalHeaders);
            return this._processResponse(res, this.requestOptions);
        });
    }
    putJson(requestUrl, obj, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            const data = JSON.stringify(obj, null, 2);
            additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
            additionalHeaders[Headers.ContentType] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.ContentType, MediaTypes.ApplicationJson);
            const res = yield this.put(requestUrl, data, additionalHeaders);
            return this._processResponse(res, this.requestOptions);
        });
    }
    patchJson(requestUrl, obj, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            const data = JSON.stringify(obj, null, 2);
            additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
            additionalHeaders[Headers.ContentType] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.ContentType, MediaTypes.ApplicationJson);
            const res = yield this.patch(requestUrl, data, additionalHeaders);
            return this._processResponse(res, this.requestOptions);
        });
    }
    /**
     * Makes a raw http request.
     * All other methods such as get, post, patch, and request ultimately call this.
     * Prefer get, del, post and patch
     */
    request(verb, requestUrl, data, headers) {
        return __awaiter(this, void 0, void 0, function* () {
            if (this._disposed) {
                throw new Error('Client has already been disposed.');
            }
            const parsedUrl = new URL(requestUrl);
            let info = this._prepareRequest(verb, parsedUrl, headers);
            // Only perform retries on reads since writes may not be idempotent.
            const maxTries = this._allowRetries && RetryableHttpVerbs.includes(verb)
                ? this._maxRetries + 1
                : 1;
            let numTries = 0;
            let response;
            do {
                response = yield this.requestRaw(info, data);
                // Check if it's an authentication challenge
                if (response &&
                    response.message &&
                    response.message.statusCode === HttpCodes.Unauthorized) {
                    let authenticationHandler;
                    for (const handler of this.handlers) {
                        if (handler.canHandleAuthentication(response)) {
                            authenticationHandler = handler;
                            break;
                        }
                    }
                    if (authenticationHandler) {
                        return authenticationHandler.handleAuthentication(this, info, data);
                    }
                    else {
                        // We have received an unauthorized response but have no handlers to handle it.
                        // Let the response return to the caller.
                        return response;
                    }
                }
                let redirectsRemaining = this._maxRedirects;
                while (response.message.statusCode &&
                    HttpRedirectCodes.includes(response.message.statusCode) &&
                    this._allowRedirects &&
                    redirectsRemaining > 0) {
                    const redirectUrl = response.message.headers['location'];
                    if (!redirectUrl) {
                        // if there's no location to redirect to, we won't
                        break;
                    }
                    const parsedRedirectUrl = new URL(redirectUrl);
                    if (parsedUrl.protocol === 'https:' &&
                        parsedUrl.protocol !== parsedRedirectUrl.protocol &&
                        !this._allowRedirectDowngrade) {
                        throw new Error('Redirect from HTTPS to HTTP protocol. This downgrade is not allowed for security reasons. If you want to allow this behavior, set the allowRedirectDowngrade option to true.');
                    }
                    // we need to finish reading the response before reassigning response
                    // which will leak the open socket.
                    yield response.readBody();
                    // strip authorization header if redirected to a different hostname
                    if (parsedRedirectUrl.hostname !== parsedUrl.hostname) {
                        for (const header in headers) {
                            // header names are case insensitive
                            if (header.toLowerCase() === 'authorization') {
                                delete headers[header];
                            }
                        }
                    }
                    // let's make the request with the new redirectUrl
                    info = this._prepareRequest(verb, parsedRedirectUrl, headers);
                    response = yield this.requestRaw(info, data);
                    redirectsRemaining--;
                }
                if (!response.message.statusCode ||
                    !HttpResponseRetryCodes.includes(response.message.statusCode)) {
                    // If not a retry code, return immediately instead of retrying
                    return response;
                }
                numTries += 1;
                if (numTries < maxTries) {
                    yield response.readBody();
                    yield this._performExponentialBackoff(numTries);
                }
            } while (numTries < maxTries);
            return response;
        });
    }
    /**
     * Needs to be called if keepAlive is set to true in request options.
     */
    dispose() {
        if (this._agent) {
            this._agent.destroy();
        }
        this._disposed = true;
    }
    /**
     * Raw request.
     * @param info
     * @param data
     */
    requestRaw(info, data) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => {
                function callbackForResult(err, res) {
                    if (err) {
                        reject(err);
                    }
                    else if (!res) {
                        // If `err` is not passed, then `res` must be passed.
                        reject(new Error('Unknown error'));
                    }
                    else {
                        resolve(res);
                    }
                }
                this.requestRawWithCallback(info, data, callbackForResult);
            });
        });
    }
    /**
     * Raw request with callback.
     * @param info
     * @param data
     * @param onResult
     */
    requestRawWithCallback(info, data, onResult) {
        if (typeof data === 'string') {
            if (!info.options.headers) {
                info.options.headers = {};
            }
            info.options.headers['Content-Length'] = Buffer.byteLength(data, 'utf8');
        }
        let callbackCalled = false;
        function handleResult(err, res) {
            if (!callbackCalled) {
                callbackCalled = true;
                onResult(err, res);
            }
        }
        const req = info.httpModule.request(info.options, (msg) => {
            const res = new HttpClientResponse(msg);
            handleResult(undefined, res);
        });
        let socket;
        req.on('socket', sock => {
            socket = sock;
        });
        // If we ever get disconnected, we want the socket to timeout eventually
        req.setTimeout(this._socketTimeout || 3 * 60000, () => {
            if (socket) {
                socket.end();
            }
            handleResult(new Error(`Request timeout: ${info.options.path}`));
        });
        req.on('error', function (err) {
            // err has statusCode property
            // res should have headers
            handleResult(err);
        });
        if (data && typeof data === 'string') {
            req.write(data, 'utf8');
        }
        if (data && typeof data !== 'string') {
            data.on('close', function () {
                req.end();
            });
            data.pipe(req);
        }
        else {
            req.end();
        }
    }
    /**
     * Gets an http agent. This function is useful when you need an http agent that handles
     * routing through a proxy server - depending upon the url and proxy environment variables.
     * @param serverUrl  The server URL where the request will be sent. For example, https://api.github.com
     */
    getAgent(serverUrl) {
        const parsedUrl = new URL(serverUrl);
        return this._getAgent(parsedUrl);
    }
    _prepareRequest(method, requestUrl, headers) {
        const info = {};
        info.parsedUrl = requestUrl;
        const usingSsl = info.parsedUrl.protocol === 'https:';
        info.httpModule = usingSsl ? https : http;
        const defaultPort = usingSsl ? 443 : 80;
        info.options = {};
        info.options.host = info.parsedUrl.hostname;
        info.options.port = info.parsedUrl.port
            ? parseInt(info.parsedUrl.port)
            : defaultPort;
        info.options.path =
            (info.parsedUrl.pathname || '') + (info.parsedUrl.search || '');
        info.options.method = method;
        info.options.headers = this._mergeHeaders(headers);
        if (this.userAgent != null) {
            info.options.headers['user-agent'] = this.userAgent;
        }
        info.options.agent = this._getAgent(info.parsedUrl);
        // gives handlers an opportunity to participate
        if (this.handlers) {
            for (const handler of this.handlers) {
                handler.prepareRequest(info.options);
            }
        }
        return info;
    }
    _mergeHeaders(headers) {
        if (this.requestOptions && this.requestOptions.headers) {
            return Object.assign({}, lowercaseKeys(this.requestOptions.headers), lowercaseKeys(headers || {}));
        }
        return lowercaseKeys(headers || {});
    }
    _getExistingOrDefaultHeader(additionalHeaders, header, _default) {
        let clientHeader;
        if (this.requestOptions && this.requestOptions.headers) {
            clientHeader = lowercaseKeys(this.requestOptions.headers)[header];
        }
        return additionalHeaders[header] || clientHeader || _default;
    }
    _getAgent(parsedUrl) {
        let agent;
        const proxyUrl = pm.getProxyUrl(parsedUrl);
        const useProxy = proxyUrl && proxyUrl.hostname;
        if (this._keepAlive && useProxy) {
            agent = this._proxyAgent;
        }
        if (this._keepAlive && !useProxy) {
            agent = this._agent;
        }
        // if agent is already assigned use that agent.
        if (agent) {
            return agent;
        }
        const usingSsl = parsedUrl.protocol === 'https:';
        let maxSockets = 100;
        if (this.requestOptions) {
            maxSockets = this.requestOptions.maxSockets || http.globalAgent.maxSockets;
        }
        // This is `useProxy` again, but we need to check `proxyURl` directly for TypeScripts's flow analysis.
        if (proxyUrl && proxyUrl.hostname) {
            const agentOptions = {
                maxSockets,
                keepAlive: this._keepAlive,
                proxy: Object.assign(Object.assign({}, ((proxyUrl.username || proxyUrl.password) && {
                    proxyAuth: `${proxyUrl.username}:${proxyUrl.password}`
                })), { host: proxyUrl.hostname, port: proxyUrl.port })
            };
            let tunnelAgent;
            const overHttps = proxyUrl.protocol === 'https:';
            if (usingSsl) {
                tunnelAgent = overHttps ? tunnel.httpsOverHttps : tunnel.httpsOverHttp;
            }
            else {
                tunnelAgent = overHttps ? tunnel.httpOverHttps : tunnel.httpOverHttp;
            }
            agent = tunnelAgent(agentOptions);
            this._proxyAgent = agent;
        }
        // if reusing agent across request and tunneling agent isn't assigned create a new agent
        if (this._keepAlive && !agent) {
            const options = { keepAlive: this._keepAlive, maxSockets };
            agent = usingSsl ? new https.Agent(options) : new http.Agent(options);
            this._agent = agent;
        }
        // if not using private agent and tunnel agent isn't setup then use global agent
        if (!agent) {
            agent = usingSsl ? https.globalAgent : http.globalAgent;
        }
        if (usingSsl && this._ignoreSslError) {
            // we don't want to set NODE_TLS_REJECT_UNAUTHORIZED=0 since that will affect request for entire process
            // http.RequestOptions doesn't expose a way to modify RequestOptions.agent.options
            // we have to cast it to any and change it directly
            agent.options = Object.assign(agent.options || {}, {
                rejectUnauthorized: false
            });
        }
        return agent;
    }
    _performExponentialBackoff(retryNumber) {
        return __awaiter(this, void 0, void 0, function* () {
            retryNumber = Math.min(ExponentialBackoffCeiling, retryNumber);
            const ms = ExponentialBackoffTimeSlice * Math.pow(2, retryNumber);
            return new Promise(resolve => setTimeout(() => resolve(), ms));
        });
    }
    _processResponse(res, options) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                const statusCode = res.message.statusCode || 0;
                const response = {
                    statusCode,
                    result: null,
                    headers: {}
                };
                // not found leads to null obj returned
                if (statusCode === HttpCodes.NotFound) {
                    resolve(response);
                }
                // get the result from the body
                function dateTimeDeserializer(key, value) {
                    if (typeof value === 'string') {
                        const a = new Date(value);
                        if (!isNaN(a.valueOf())) {
                            return a;
                        }
                    }
                    return value;
                }
                let obj;
                let contents;
                try {
                    contents = yield res.readBody();
                    if (contents && contents.length > 0) {
                        if (options && options.deserializeDates) {
                            obj = JSON.parse(contents, dateTimeDeserializer);
                        }
                        else {
                            obj = JSON.parse(contents);
                        }
                        response.result = obj;
                    }
                    response.headers = res.message.headers;
                }
                catch (err) {
                    // Invalid resource (contents not json);  leaving result obj null
                }
                // note that 3xx redirects are handled by the http layer.
                if (statusCode > 299) {
                    let msg;
                    // if exception/error in body, attempt to get better error
                    if (obj && obj.message) {
                        msg = obj.message;
                    }
                    else if (contents && contents.length > 0) {
                        // it may be the case that the exception is in the body message as string
                        msg = contents;
                    }
                    else {
                        msg = `Failed request: (${statusCode})`;
                    }
                    const err = new HttpClientError(msg, statusCode);
                    err.result = response.result;
                    reject(err);
                }
                else {
                    resolve(response);
                }
            }));
        });
    }
}
exports.HttpClient = HttpClient;
const lowercaseKeys = (obj) => Object.keys(obj).reduce((c, k) => ((c[k.toLowerCase()] = obj[k]), c), {});
//# sourceMappingURL=index.js.map

/***/ }),

/***/ 9835:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.checkBypass = exports.getProxyUrl = void 0;
function getProxyUrl(reqUrl) {
    const usingSsl = reqUrl.protocol === 'https:';
    if (checkBypass(reqUrl)) {
        return undefined;
    }
    const proxyVar = (() => {
        if (usingSsl) {
            return process.env['https_proxy'] || process.env['HTTPS_PROXY'];
        }
        else {
            return process.env['http_proxy'] || process.env['HTTP_PROXY'];
        }
    })();
    if (proxyVar) {
        try {
            return new URL(proxyVar);
        }
        catch (_a) {
            if (!proxyVar.startsWith('http://') && !proxyVar.startsWith('https://'))
                return new URL(`http://${proxyVar}`);
        }
    }
    else {
        return undefined;
    }
}
exports.getProxyUrl = getProxyUrl;
function checkBypass(reqUrl) {
    if (!reqUrl.hostname) {
        return false;
    }
    const reqHost = reqUrl.hostname;
    if (isLoopbackAddress(reqHost)) {
        return true;
    }
    const noProxy = process.env['no_proxy'] || process.env['NO_PROXY'] || '';
    if (!noProxy) {
        return false;
    }
    // Determine the request port
    let reqPort;
    if (reqUrl.port) {
        reqPort = Number(reqUrl.port);
    }
    else if (reqUrl.protocol === 'http:') {
        reqPort = 80;
    }
    else if (reqUrl.protocol === 'https:') {
        reqPort = 443;
    }
    // Format the request hostname and hostname with port
    const upperReqHosts = [reqUrl.hostname.toUpperCase()];
    if (typeof reqPort === 'number') {
        upperReqHosts.push(`${upperReqHosts[0]}:${reqPort}`);
    }
    // Compare request host against noproxy
    for (const upperNoProxyItem of noProxy
        .split(',')
        .map(x => x.trim().toUpperCase())
        .filter(x => x)) {
        if (upperNoProxyItem === '*' ||
            upperReqHosts.some(x => x === upperNoProxyItem ||
                x.endsWith(`.${upperNoProxyItem}`) ||
                (upperNoProxyItem.startsWith('.') &&
                    x.endsWith(`${upperNoProxyItem}`)))) {
            return true;
        }
    }
    return false;
}
exports.checkBypass = checkBypass;
function isLoopbackAddress(host) {
    const hostLower = host.toLowerCase();
    return (hostLower === 'localhost' ||
        hostLower.startsWith('127.') ||
        hostLower.startsWith('[::1]') ||
        hostLower.startsWith('[0:0:0:0:0:0:0:1]'));
}
//# sourceMappingURL=proxy.js.map

/***/ }),

/***/ 4682:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.resolveHttpAuthSchemeConfig = exports.defaultECRHttpAuthSchemeProvider = exports.defaultECRHttpAuthSchemeParametersProvider = void 0;
const core_1 = __nccwpck_require__(9963);
const util_middleware_1 = __nccwpck_require__(2390);
const defaultECRHttpAuthSchemeParametersProvider = async (config, context, input) => {
    return {
        operation: (0, util_middleware_1.getSmithyContext)(context).operation,
        region: (await (0, util_middleware_1.normalizeProvider)(config.region)()) ||
            (() => {
                throw new Error("expected `region` to be configured for `aws.auth#sigv4`");
            })(),
    };
};
exports.defaultECRHttpAuthSchemeParametersProvider = defaultECRHttpAuthSchemeParametersProvider;
function createAwsAuthSigv4HttpAuthOption(authParameters) {
    return {
        schemeId: "aws.auth#sigv4",
        signingProperties: {
            name: "ecr",
            region: authParameters.region,
        },
        propertiesExtractor: (config, context) => ({
            signingProperties: {
                config,
                context,
            },
        }),
    };
}
const defaultECRHttpAuthSchemeProvider = (authParameters) => {
    const options = [];
    switch (authParameters.operation) {
        default: {
            options.push(createAwsAuthSigv4HttpAuthOption(authParameters));
        }
    }
    return options;
};
exports.defaultECRHttpAuthSchemeProvider = defaultECRHttpAuthSchemeProvider;
const resolveHttpAuthSchemeConfig = (config) => {
    const config_0 = (0, core_1.resolveAwsSdkSigV4Config)(config);
    return {
        ...config_0,
    };
};
exports.resolveHttpAuthSchemeConfig = resolveHttpAuthSchemeConfig;


/***/ }),

/***/ 1610:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.defaultEndpointResolver = void 0;
const util_endpoints_1 = __nccwpck_require__(3350);
const util_endpoints_2 = __nccwpck_require__(5473);
const ruleset_1 = __nccwpck_require__(4053);
const defaultEndpointResolver = (endpointParams, context = {}) => {
    return (0, util_endpoints_2.resolveEndpoint)(ruleset_1.ruleSet, {
        endpointParams: endpointParams,
        logger: context.logger,
    });
};
exports.defaultEndpointResolver = defaultEndpointResolver;
util_endpoints_2.customEndpointFunctions.aws = util_endpoints_1.awsEndpointFunctions;


/***/ }),

/***/ 4053:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ruleSet = void 0;
const v = "required", w = "fn", x = "argv", y = "ref";
const a = true, b = "isSet", c = "booleanEquals", d = "error", e = "endpoint", f = "tree", g = "PartitionResult", h = "stringEquals", i = { [v]: false, "type": "String" }, j = { [v]: true, "default": false, "type": "Boolean" }, k = { [y]: "Endpoint" }, l = { [w]: c, [x]: [{ [y]: "UseFIPS" }, true] }, m = { [w]: c, [x]: [{ [y]: "UseDualStack" }, true] }, n = {}, o = { [w]: "getAttr", [x]: [{ [y]: g }, "supportsFIPS"] }, p = { [w]: c, [x]: [true, { [w]: "getAttr", [x]: [{ [y]: g }, "supportsDualStack"] }] }, q = { [w]: "getAttr", [x]: [{ [y]: g }, "name"] }, r = { "url": "https://ecr-fips.{Region}.amazonaws.com", "properties": {}, "headers": {} }, s = [l], t = [m], u = [{ [y]: "Region" }];
const _data = { version: "1.0", parameters: { Region: i, UseDualStack: j, UseFIPS: j, Endpoint: i }, rules: [{ conditions: [{ [w]: b, [x]: [k] }], rules: [{ conditions: s, error: "Invalid Configuration: FIPS and custom endpoint are not supported", type: d }, { conditions: t, error: "Invalid Configuration: Dualstack and custom endpoint are not supported", type: d }, { endpoint: { url: k, properties: n, headers: n }, type: e }], type: f }, { conditions: [{ [w]: b, [x]: u }], rules: [{ conditions: [{ [w]: "aws.partition", [x]: u, assign: g }], rules: [{ conditions: [l, m], rules: [{ conditions: [{ [w]: c, [x]: [a, o] }, p], rules: [{ endpoint: { url: "https://api.ecr-fips.{Region}.{PartitionResult#dualStackDnsSuffix}", properties: n, headers: n }, type: e }], type: f }, { error: "FIPS and DualStack are enabled, but this partition does not support one or both", type: d }], type: f }, { conditions: s, rules: [{ conditions: [{ [w]: c, [x]: [o, a] }], rules: [{ conditions: [{ [w]: h, [x]: [q, "aws"] }], endpoint: r, type: e }, { conditions: [{ [w]: h, [x]: [q, "aws-us-gov"] }], endpoint: r, type: e }, { endpoint: { url: "https://api.ecr-fips.{Region}.{PartitionResult#dnsSuffix}", properties: n, headers: n }, type: e }], type: f }, { error: "FIPS is enabled but this partition does not support FIPS", type: d }], type: f }, { conditions: t, rules: [{ conditions: [p], rules: [{ endpoint: { url: "https://api.ecr.{Region}.{PartitionResult#dualStackDnsSuffix}", properties: n, headers: n }, type: e }], type: f }, { error: "DualStack is enabled but this partition does not support DualStack", type: d }], type: f }, { endpoint: { url: "https://api.ecr.{Region}.{PartitionResult#dnsSuffix}", properties: n, headers: n }, type: e }], type: f }], type: f }, { error: "Invalid Configuration: Missing Region", type: d }] };
exports.ruleSet = _data;


/***/ }),

/***/ 8923:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  BatchCheckLayerAvailabilityCommand: () => BatchCheckLayerAvailabilityCommand,
  BatchDeleteImageCommand: () => BatchDeleteImageCommand,
  BatchGetImageCommand: () => BatchGetImageCommand,
  BatchGetRepositoryScanningConfigurationCommand: () => BatchGetRepositoryScanningConfigurationCommand,
  CompleteLayerUploadCommand: () => CompleteLayerUploadCommand,
  CreatePullThroughCacheRuleCommand: () => CreatePullThroughCacheRuleCommand,
  CreateRepositoryCommand: () => CreateRepositoryCommand,
  CreateRepositoryCreationTemplateCommand: () => CreateRepositoryCreationTemplateCommand,
  DeleteLifecyclePolicyCommand: () => DeleteLifecyclePolicyCommand,
  DeletePullThroughCacheRuleCommand: () => DeletePullThroughCacheRuleCommand,
  DeleteRegistryPolicyCommand: () => DeleteRegistryPolicyCommand,
  DeleteRepositoryCommand: () => DeleteRepositoryCommand,
  DeleteRepositoryCreationTemplateCommand: () => DeleteRepositoryCreationTemplateCommand,
  DeleteRepositoryPolicyCommand: () => DeleteRepositoryPolicyCommand,
  DescribeImageReplicationStatusCommand: () => DescribeImageReplicationStatusCommand,
  DescribeImageScanFindingsCommand: () => DescribeImageScanFindingsCommand,
  DescribeImagesCommand: () => DescribeImagesCommand,
  DescribePullThroughCacheRulesCommand: () => DescribePullThroughCacheRulesCommand,
  DescribeRegistryCommand: () => DescribeRegistryCommand,
  DescribeRepositoriesCommand: () => DescribeRepositoriesCommand,
  DescribeRepositoryCreationTemplatesCommand: () => DescribeRepositoryCreationTemplatesCommand,
  ECR: () => ECR,
  ECRClient: () => ECRClient,
  ECRServiceException: () => ECRServiceException,
  EmptyUploadException: () => EmptyUploadException,
  EncryptionType: () => EncryptionType,
  FindingSeverity: () => FindingSeverity,
  GetAuthorizationTokenCommand: () => GetAuthorizationTokenCommand,
  GetDownloadUrlForLayerCommand: () => GetDownloadUrlForLayerCommand,
  GetLifecyclePolicyCommand: () => GetLifecyclePolicyCommand,
  GetLifecyclePolicyPreviewCommand: () => GetLifecyclePolicyPreviewCommand,
  GetRegistryPolicyCommand: () => GetRegistryPolicyCommand,
  GetRegistryScanningConfigurationCommand: () => GetRegistryScanningConfigurationCommand,
  GetRepositoryPolicyCommand: () => GetRepositoryPolicyCommand,
  ImageActionType: () => ImageActionType,
  ImageAlreadyExistsException: () => ImageAlreadyExistsException,
  ImageDigestDoesNotMatchException: () => ImageDigestDoesNotMatchException,
  ImageFailureCode: () => ImageFailureCode,
  ImageNotFoundException: () => ImageNotFoundException,
  ImageTagAlreadyExistsException: () => ImageTagAlreadyExistsException,
  ImageTagMutability: () => ImageTagMutability,
  InitiateLayerUploadCommand: () => InitiateLayerUploadCommand,
  InvalidLayerException: () => InvalidLayerException,
  InvalidLayerPartException: () => InvalidLayerPartException,
  InvalidParameterException: () => InvalidParameterException,
  InvalidTagParameterException: () => InvalidTagParameterException,
  KmsException: () => KmsException,
  LayerAlreadyExistsException: () => LayerAlreadyExistsException,
  LayerAvailability: () => LayerAvailability,
  LayerFailureCode: () => LayerFailureCode,
  LayerInaccessibleException: () => LayerInaccessibleException,
  LayerPartTooSmallException: () => LayerPartTooSmallException,
  LayersNotFoundException: () => LayersNotFoundException,
  LifecyclePolicyNotFoundException: () => LifecyclePolicyNotFoundException,
  LifecyclePolicyPreviewInProgressException: () => LifecyclePolicyPreviewInProgressException,
  LifecyclePolicyPreviewNotFoundException: () => LifecyclePolicyPreviewNotFoundException,
  LifecyclePolicyPreviewStatus: () => LifecyclePolicyPreviewStatus,
  LimitExceededException: () => LimitExceededException,
  ListImagesCommand: () => ListImagesCommand,
  ListTagsForResourceCommand: () => ListTagsForResourceCommand,
  PullThroughCacheRuleAlreadyExistsException: () => PullThroughCacheRuleAlreadyExistsException,
  PullThroughCacheRuleNotFoundException: () => PullThroughCacheRuleNotFoundException,
  PutImageCommand: () => PutImageCommand,
  PutImageScanningConfigurationCommand: () => PutImageScanningConfigurationCommand,
  PutImageTagMutabilityCommand: () => PutImageTagMutabilityCommand,
  PutLifecyclePolicyCommand: () => PutLifecyclePolicyCommand,
  PutRegistryPolicyCommand: () => PutRegistryPolicyCommand,
  PutRegistryScanningConfigurationCommand: () => PutRegistryScanningConfigurationCommand,
  PutReplicationConfigurationCommand: () => PutReplicationConfigurationCommand,
  RCTAppliedFor: () => RCTAppliedFor,
  ReferencedImagesNotFoundException: () => ReferencedImagesNotFoundException,
  RegistryPolicyNotFoundException: () => RegistryPolicyNotFoundException,
  ReplicationStatus: () => ReplicationStatus,
  RepositoryAlreadyExistsException: () => RepositoryAlreadyExistsException,
  RepositoryFilterType: () => RepositoryFilterType,
  RepositoryNotEmptyException: () => RepositoryNotEmptyException,
  RepositoryNotFoundException: () => RepositoryNotFoundException,
  RepositoryPolicyNotFoundException: () => RepositoryPolicyNotFoundException,
  ScanFrequency: () => ScanFrequency,
  ScanNotFoundException: () => ScanNotFoundException,
  ScanStatus: () => ScanStatus,
  ScanType: () => ScanType,
  ScanningConfigurationFailureCode: () => ScanningConfigurationFailureCode,
  ScanningRepositoryFilterType: () => ScanningRepositoryFilterType,
  SecretNotFoundException: () => SecretNotFoundException,
  ServerException: () => ServerException,
  SetRepositoryPolicyCommand: () => SetRepositoryPolicyCommand,
  StartImageScanCommand: () => StartImageScanCommand,
  StartLifecyclePolicyPreviewCommand: () => StartLifecyclePolicyPreviewCommand,
  TagResourceCommand: () => TagResourceCommand,
  TagStatus: () => TagStatus,
  TemplateAlreadyExistsException: () => TemplateAlreadyExistsException,
  TemplateNotFoundException: () => TemplateNotFoundException,
  TooManyTagsException: () => TooManyTagsException,
  UnableToAccessSecretException: () => UnableToAccessSecretException,
  UnableToDecryptSecretValueException: () => UnableToDecryptSecretValueException,
  UnableToGetUpstreamImageException: () => UnableToGetUpstreamImageException,
  UnableToGetUpstreamLayerException: () => UnableToGetUpstreamLayerException,
  UnsupportedImageTypeException: () => UnsupportedImageTypeException,
  UnsupportedUpstreamRegistryException: () => UnsupportedUpstreamRegistryException,
  UntagResourceCommand: () => UntagResourceCommand,
  UpdatePullThroughCacheRuleCommand: () => UpdatePullThroughCacheRuleCommand,
  UpdateRepositoryCreationTemplateCommand: () => UpdateRepositoryCreationTemplateCommand,
  UploadLayerPartCommand: () => UploadLayerPartCommand,
  UploadNotFoundException: () => UploadNotFoundException,
  UpstreamRegistry: () => UpstreamRegistry,
  ValidatePullThroughCacheRuleCommand: () => ValidatePullThroughCacheRuleCommand,
  ValidationException: () => ValidationException,
  __Client: () => import_smithy_client.Client,
  paginateDescribeImageScanFindings: () => paginateDescribeImageScanFindings,
  paginateDescribeImages: () => paginateDescribeImages,
  paginateDescribePullThroughCacheRules: () => paginateDescribePullThroughCacheRules,
  paginateDescribeRepositories: () => paginateDescribeRepositories,
  paginateDescribeRepositoryCreationTemplates: () => paginateDescribeRepositoryCreationTemplates,
  paginateGetLifecyclePolicyPreview: () => paginateGetLifecyclePolicyPreview,
  paginateListImages: () => paginateListImages,
  waitForImageScanComplete: () => waitForImageScanComplete,
  waitForLifecyclePolicyPreviewComplete: () => waitForLifecyclePolicyPreviewComplete,
  waitUntilImageScanComplete: () => waitUntilImageScanComplete,
  waitUntilLifecyclePolicyPreviewComplete: () => waitUntilLifecyclePolicyPreviewComplete
});
module.exports = __toCommonJS(src_exports);

// src/ECRClient.ts
var import_middleware_host_header = __nccwpck_require__(2545);
var import_middleware_logger = __nccwpck_require__(14);
var import_middleware_recursion_detection = __nccwpck_require__(5525);
var import_middleware_user_agent = __nccwpck_require__(4688);
var import_config_resolver = __nccwpck_require__(3098);
var import_core = __nccwpck_require__(5829);
var import_middleware_content_length = __nccwpck_require__(2800);
var import_middleware_endpoint = __nccwpck_require__(2918);
var import_middleware_retry = __nccwpck_require__(6039);

var import_httpAuthSchemeProvider = __nccwpck_require__(4682);

// src/endpoint/EndpointParameters.ts
var resolveClientEndpointParameters = /* @__PURE__ */ __name((options) => {
  return {
    ...options,
    useDualstackEndpoint: options.useDualstackEndpoint ?? false,
    useFipsEndpoint: options.useFipsEndpoint ?? false,
    defaultSigningName: "ecr"
  };
}, "resolveClientEndpointParameters");
var commonParams = {
  UseFIPS: { type: "builtInParams", name: "useFipsEndpoint" },
  Endpoint: { type: "builtInParams", name: "endpoint" },
  Region: { type: "builtInParams", name: "region" },
  UseDualStack: { type: "builtInParams", name: "useDualstackEndpoint" }
};

// src/ECRClient.ts
var import_runtimeConfig = __nccwpck_require__(869);

// src/runtimeExtensions.ts
var import_region_config_resolver = __nccwpck_require__(8156);
var import_protocol_http = __nccwpck_require__(4418);
var import_smithy_client = __nccwpck_require__(3570);

// src/auth/httpAuthExtensionConfiguration.ts
var getHttpAuthExtensionConfiguration = /* @__PURE__ */ __name((runtimeConfig) => {
  const _httpAuthSchemes = runtimeConfig.httpAuthSchemes;
  let _httpAuthSchemeProvider = runtimeConfig.httpAuthSchemeProvider;
  let _credentials = runtimeConfig.credentials;
  return {
    setHttpAuthScheme(httpAuthScheme) {
      const index = _httpAuthSchemes.findIndex((scheme) => scheme.schemeId === httpAuthScheme.schemeId);
      if (index === -1) {
        _httpAuthSchemes.push(httpAuthScheme);
      } else {
        _httpAuthSchemes.splice(index, 1, httpAuthScheme);
      }
    },
    httpAuthSchemes() {
      return _httpAuthSchemes;
    },
    setHttpAuthSchemeProvider(httpAuthSchemeProvider) {
      _httpAuthSchemeProvider = httpAuthSchemeProvider;
    },
    httpAuthSchemeProvider() {
      return _httpAuthSchemeProvider;
    },
    setCredentials(credentials) {
      _credentials = credentials;
    },
    credentials() {
      return _credentials;
    }
  };
}, "getHttpAuthExtensionConfiguration");
var resolveHttpAuthRuntimeConfig = /* @__PURE__ */ __name((config) => {
  return {
    httpAuthSchemes: config.httpAuthSchemes(),
    httpAuthSchemeProvider: config.httpAuthSchemeProvider(),
    credentials: config.credentials()
  };
}, "resolveHttpAuthRuntimeConfig");

// src/runtimeExtensions.ts
var asPartial = /* @__PURE__ */ __name((t) => t, "asPartial");
var resolveRuntimeExtensions = /* @__PURE__ */ __name((runtimeConfig, extensions) => {
  const extensionConfiguration = {
    ...asPartial((0, import_region_config_resolver.getAwsRegionExtensionConfiguration)(runtimeConfig)),
    ...asPartial((0, import_smithy_client.getDefaultExtensionConfiguration)(runtimeConfig)),
    ...asPartial((0, import_protocol_http.getHttpHandlerExtensionConfiguration)(runtimeConfig)),
    ...asPartial(getHttpAuthExtensionConfiguration(runtimeConfig))
  };
  extensions.forEach((extension) => extension.configure(extensionConfiguration));
  return {
    ...runtimeConfig,
    ...(0, import_region_config_resolver.resolveAwsRegionExtensionConfiguration)(extensionConfiguration),
    ...(0, import_smithy_client.resolveDefaultRuntimeConfig)(extensionConfiguration),
    ...(0, import_protocol_http.resolveHttpHandlerRuntimeConfig)(extensionConfiguration),
    ...resolveHttpAuthRuntimeConfig(extensionConfiguration)
  };
}, "resolveRuntimeExtensions");

// src/ECRClient.ts
var _ECRClient = class _ECRClient extends import_smithy_client.Client {
  constructor(...[configuration]) {
    const _config_0 = (0, import_runtimeConfig.getRuntimeConfig)(configuration || {});
    const _config_1 = resolveClientEndpointParameters(_config_0);
    const _config_2 = (0, import_middleware_user_agent.resolveUserAgentConfig)(_config_1);
    const _config_3 = (0, import_middleware_retry.resolveRetryConfig)(_config_2);
    const _config_4 = (0, import_config_resolver.resolveRegionConfig)(_config_3);
    const _config_5 = (0, import_middleware_host_header.resolveHostHeaderConfig)(_config_4);
    const _config_6 = (0, import_middleware_endpoint.resolveEndpointConfig)(_config_5);
    const _config_7 = (0, import_httpAuthSchemeProvider.resolveHttpAuthSchemeConfig)(_config_6);
    const _config_8 = resolveRuntimeExtensions(_config_7, (configuration == null ? void 0 : configuration.extensions) || []);
    super(_config_8);
    this.config = _config_8;
    this.middlewareStack.use((0, import_middleware_user_agent.getUserAgentPlugin)(this.config));
    this.middlewareStack.use((0, import_middleware_retry.getRetryPlugin)(this.config));
    this.middlewareStack.use((0, import_middleware_content_length.getContentLengthPlugin)(this.config));
    this.middlewareStack.use((0, import_middleware_host_header.getHostHeaderPlugin)(this.config));
    this.middlewareStack.use((0, import_middleware_logger.getLoggerPlugin)(this.config));
    this.middlewareStack.use((0, import_middleware_recursion_detection.getRecursionDetectionPlugin)(this.config));
    this.middlewareStack.use(
      (0, import_core.getHttpAuthSchemeEndpointRuleSetPlugin)(this.config, {
        httpAuthSchemeParametersProvider: import_httpAuthSchemeProvider.defaultECRHttpAuthSchemeParametersProvider,
        identityProviderConfigProvider: async (config) => new import_core.DefaultIdentityProviderConfig({
          "aws.auth#sigv4": config.credentials
        })
      })
    );
    this.middlewareStack.use((0, import_core.getHttpSigningPlugin)(this.config));
  }
  /**
   * Destroy underlying resources, like sockets. It's usually not necessary to do this.
   * However in Node.js, it's best to explicitly shut down the client's agent when it is no longer needed.
   * Otherwise, sockets might stay open for quite a long time before the server terminates them.
   */
  destroy() {
    super.destroy();
  }
};
__name(_ECRClient, "ECRClient");
var ECRClient = _ECRClient;

// src/ECR.ts


// src/commands/BatchCheckLayerAvailabilityCommand.ts

var import_middleware_serde = __nccwpck_require__(1238);


// src/protocols/Aws_json1_1.ts
var import_core2 = __nccwpck_require__(9963);



// src/models/ECRServiceException.ts

var _ECRServiceException = class _ECRServiceException extends import_smithy_client.ServiceException {
  /**
   * @internal
   */
  constructor(options) {
    super(options);
    Object.setPrototypeOf(this, _ECRServiceException.prototype);
  }
};
__name(_ECRServiceException, "ECRServiceException");
var ECRServiceException = _ECRServiceException;

// src/models/models_0.ts
var LayerFailureCode = {
  InvalidLayerDigest: "InvalidLayerDigest",
  MissingLayerDigest: "MissingLayerDigest"
};
var LayerAvailability = {
  AVAILABLE: "AVAILABLE",
  UNAVAILABLE: "UNAVAILABLE"
};
var _InvalidParameterException = class _InvalidParameterException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "InvalidParameterException",
      $fault: "client",
      ...opts
    });
    this.name = "InvalidParameterException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _InvalidParameterException.prototype);
  }
};
__name(_InvalidParameterException, "InvalidParameterException");
var InvalidParameterException = _InvalidParameterException;
var _RepositoryNotFoundException = class _RepositoryNotFoundException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "RepositoryNotFoundException",
      $fault: "client",
      ...opts
    });
    this.name = "RepositoryNotFoundException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _RepositoryNotFoundException.prototype);
  }
};
__name(_RepositoryNotFoundException, "RepositoryNotFoundException");
var RepositoryNotFoundException = _RepositoryNotFoundException;
var _ServerException = class _ServerException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "ServerException",
      $fault: "server",
      ...opts
    });
    this.name = "ServerException";
    this.$fault = "server";
    Object.setPrototypeOf(this, _ServerException.prototype);
  }
};
__name(_ServerException, "ServerException");
var ServerException = _ServerException;
var ImageFailureCode = {
  ImageNotFound: "ImageNotFound",
  ImageReferencedByManifestList: "ImageReferencedByManifestList",
  ImageTagDoesNotMatchDigest: "ImageTagDoesNotMatchDigest",
  InvalidImageDigest: "InvalidImageDigest",
  InvalidImageTag: "InvalidImageTag",
  KmsError: "KmsError",
  MissingDigestAndTag: "MissingDigestAndTag",
  UpstreamAccessDenied: "UpstreamAccessDenied",
  UpstreamTooManyRequests: "UpstreamTooManyRequests",
  UpstreamUnavailable: "UpstreamUnavailable"
};
var _LimitExceededException = class _LimitExceededException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "LimitExceededException",
      $fault: "client",
      ...opts
    });
    this.name = "LimitExceededException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _LimitExceededException.prototype);
  }
};
__name(_LimitExceededException, "LimitExceededException");
var LimitExceededException = _LimitExceededException;
var _UnableToGetUpstreamImageException = class _UnableToGetUpstreamImageException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "UnableToGetUpstreamImageException",
      $fault: "client",
      ...opts
    });
    this.name = "UnableToGetUpstreamImageException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _UnableToGetUpstreamImageException.prototype);
  }
};
__name(_UnableToGetUpstreamImageException, "UnableToGetUpstreamImageException");
var UnableToGetUpstreamImageException = _UnableToGetUpstreamImageException;
var ScanningConfigurationFailureCode = {
  REPOSITORY_NOT_FOUND: "REPOSITORY_NOT_FOUND"
};
var ScanningRepositoryFilterType = {
  WILDCARD: "WILDCARD"
};
var ScanFrequency = {
  CONTINUOUS_SCAN: "CONTINUOUS_SCAN",
  MANUAL: "MANUAL",
  SCAN_ON_PUSH: "SCAN_ON_PUSH"
};
var _ValidationException = class _ValidationException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "ValidationException",
      $fault: "client",
      ...opts
    });
    this.name = "ValidationException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _ValidationException.prototype);
  }
};
__name(_ValidationException, "ValidationException");
var ValidationException = _ValidationException;
var _EmptyUploadException = class _EmptyUploadException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "EmptyUploadException",
      $fault: "client",
      ...opts
    });
    this.name = "EmptyUploadException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _EmptyUploadException.prototype);
  }
};
__name(_EmptyUploadException, "EmptyUploadException");
var EmptyUploadException = _EmptyUploadException;
var _InvalidLayerException = class _InvalidLayerException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "InvalidLayerException",
      $fault: "client",
      ...opts
    });
    this.name = "InvalidLayerException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _InvalidLayerException.prototype);
  }
};
__name(_InvalidLayerException, "InvalidLayerException");
var InvalidLayerException = _InvalidLayerException;
var _KmsException = class _KmsException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "KmsException",
      $fault: "client",
      ...opts
    });
    this.name = "KmsException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _KmsException.prototype);
    this.kmsError = opts.kmsError;
  }
};
__name(_KmsException, "KmsException");
var KmsException = _KmsException;
var _LayerAlreadyExistsException = class _LayerAlreadyExistsException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "LayerAlreadyExistsException",
      $fault: "client",
      ...opts
    });
    this.name = "LayerAlreadyExistsException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _LayerAlreadyExistsException.prototype);
  }
};
__name(_LayerAlreadyExistsException, "LayerAlreadyExistsException");
var LayerAlreadyExistsException = _LayerAlreadyExistsException;
var _LayerPartTooSmallException = class _LayerPartTooSmallException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "LayerPartTooSmallException",
      $fault: "client",
      ...opts
    });
    this.name = "LayerPartTooSmallException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _LayerPartTooSmallException.prototype);
  }
};
__name(_LayerPartTooSmallException, "LayerPartTooSmallException");
var LayerPartTooSmallException = _LayerPartTooSmallException;
var _UploadNotFoundException = class _UploadNotFoundException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "UploadNotFoundException",
      $fault: "client",
      ...opts
    });
    this.name = "UploadNotFoundException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _UploadNotFoundException.prototype);
  }
};
__name(_UploadNotFoundException, "UploadNotFoundException");
var UploadNotFoundException = _UploadNotFoundException;
var UpstreamRegistry = {
  AzureContainerRegistry: "azure-container-registry",
  DockerHub: "docker-hub",
  EcrPublic: "ecr-public",
  GitHubContainerRegistry: "github-container-registry",
  GitLabContainerRegistry: "gitlab-container-registry",
  K8s: "k8s",
  Quay: "quay"
};
var _PullThroughCacheRuleAlreadyExistsException = class _PullThroughCacheRuleAlreadyExistsException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "PullThroughCacheRuleAlreadyExistsException",
      $fault: "client",
      ...opts
    });
    this.name = "PullThroughCacheRuleAlreadyExistsException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _PullThroughCacheRuleAlreadyExistsException.prototype);
  }
};
__name(_PullThroughCacheRuleAlreadyExistsException, "PullThroughCacheRuleAlreadyExistsException");
var PullThroughCacheRuleAlreadyExistsException = _PullThroughCacheRuleAlreadyExistsException;
var _SecretNotFoundException = class _SecretNotFoundException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "SecretNotFoundException",
      $fault: "client",
      ...opts
    });
    this.name = "SecretNotFoundException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _SecretNotFoundException.prototype);
  }
};
__name(_SecretNotFoundException, "SecretNotFoundException");
var SecretNotFoundException = _SecretNotFoundException;
var _UnableToAccessSecretException = class _UnableToAccessSecretException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "UnableToAccessSecretException",
      $fault: "client",
      ...opts
    });
    this.name = "UnableToAccessSecretException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _UnableToAccessSecretException.prototype);
  }
};
__name(_UnableToAccessSecretException, "UnableToAccessSecretException");
var UnableToAccessSecretException = _UnableToAccessSecretException;
var _UnableToDecryptSecretValueException = class _UnableToDecryptSecretValueException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "UnableToDecryptSecretValueException",
      $fault: "client",
      ...opts
    });
    this.name = "UnableToDecryptSecretValueException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _UnableToDecryptSecretValueException.prototype);
  }
};
__name(_UnableToDecryptSecretValueException, "UnableToDecryptSecretValueException");
var UnableToDecryptSecretValueException = _UnableToDecryptSecretValueException;
var _UnsupportedUpstreamRegistryException = class _UnsupportedUpstreamRegistryException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "UnsupportedUpstreamRegistryException",
      $fault: "client",
      ...opts
    });
    this.name = "UnsupportedUpstreamRegistryException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _UnsupportedUpstreamRegistryException.prototype);
  }
};
__name(_UnsupportedUpstreamRegistryException, "UnsupportedUpstreamRegistryException");
var UnsupportedUpstreamRegistryException = _UnsupportedUpstreamRegistryException;
var EncryptionType = {
  AES256: "AES256",
  KMS: "KMS"
};
var ImageTagMutability = {
  IMMUTABLE: "IMMUTABLE",
  MUTABLE: "MUTABLE"
};
var _InvalidTagParameterException = class _InvalidTagParameterException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "InvalidTagParameterException",
      $fault: "client",
      ...opts
    });
    this.name = "InvalidTagParameterException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _InvalidTagParameterException.prototype);
  }
};
__name(_InvalidTagParameterException, "InvalidTagParameterException");
var InvalidTagParameterException = _InvalidTagParameterException;
var _RepositoryAlreadyExistsException = class _RepositoryAlreadyExistsException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "RepositoryAlreadyExistsException",
      $fault: "client",
      ...opts
    });
    this.name = "RepositoryAlreadyExistsException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _RepositoryAlreadyExistsException.prototype);
  }
};
__name(_RepositoryAlreadyExistsException, "RepositoryAlreadyExistsException");
var RepositoryAlreadyExistsException = _RepositoryAlreadyExistsException;
var _TooManyTagsException = class _TooManyTagsException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "TooManyTagsException",
      $fault: "client",
      ...opts
    });
    this.name = "TooManyTagsException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _TooManyTagsException.prototype);
  }
};
__name(_TooManyTagsException, "TooManyTagsException");
var TooManyTagsException = _TooManyTagsException;
var RCTAppliedFor = {
  PULL_THROUGH_CACHE: "PULL_THROUGH_CACHE",
  REPLICATION: "REPLICATION"
};
var _TemplateAlreadyExistsException = class _TemplateAlreadyExistsException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "TemplateAlreadyExistsException",
      $fault: "client",
      ...opts
    });
    this.name = "TemplateAlreadyExistsException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _TemplateAlreadyExistsException.prototype);
  }
};
__name(_TemplateAlreadyExistsException, "TemplateAlreadyExistsException");
var TemplateAlreadyExistsException = _TemplateAlreadyExistsException;
var _LifecyclePolicyNotFoundException = class _LifecyclePolicyNotFoundException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "LifecyclePolicyNotFoundException",
      $fault: "client",
      ...opts
    });
    this.name = "LifecyclePolicyNotFoundException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _LifecyclePolicyNotFoundException.prototype);
  }
};
__name(_LifecyclePolicyNotFoundException, "LifecyclePolicyNotFoundException");
var LifecyclePolicyNotFoundException = _LifecyclePolicyNotFoundException;
var _PullThroughCacheRuleNotFoundException = class _PullThroughCacheRuleNotFoundException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "PullThroughCacheRuleNotFoundException",
      $fault: "client",
      ...opts
    });
    this.name = "PullThroughCacheRuleNotFoundException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _PullThroughCacheRuleNotFoundException.prototype);
  }
};
__name(_PullThroughCacheRuleNotFoundException, "PullThroughCacheRuleNotFoundException");
var PullThroughCacheRuleNotFoundException = _PullThroughCacheRuleNotFoundException;
var _RegistryPolicyNotFoundException = class _RegistryPolicyNotFoundException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "RegistryPolicyNotFoundException",
      $fault: "client",
      ...opts
    });
    this.name = "RegistryPolicyNotFoundException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _RegistryPolicyNotFoundException.prototype);
  }
};
__name(_RegistryPolicyNotFoundException, "RegistryPolicyNotFoundException");
var RegistryPolicyNotFoundException = _RegistryPolicyNotFoundException;
var _RepositoryNotEmptyException = class _RepositoryNotEmptyException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "RepositoryNotEmptyException",
      $fault: "client",
      ...opts
    });
    this.name = "RepositoryNotEmptyException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _RepositoryNotEmptyException.prototype);
  }
};
__name(_RepositoryNotEmptyException, "RepositoryNotEmptyException");
var RepositoryNotEmptyException = _RepositoryNotEmptyException;
var _TemplateNotFoundException = class _TemplateNotFoundException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "TemplateNotFoundException",
      $fault: "client",
      ...opts
    });
    this.name = "TemplateNotFoundException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _TemplateNotFoundException.prototype);
  }
};
__name(_TemplateNotFoundException, "TemplateNotFoundException");
var TemplateNotFoundException = _TemplateNotFoundException;
var _RepositoryPolicyNotFoundException = class _RepositoryPolicyNotFoundException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "RepositoryPolicyNotFoundException",
      $fault: "client",
      ...opts
    });
    this.name = "RepositoryPolicyNotFoundException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _RepositoryPolicyNotFoundException.prototype);
  }
};
__name(_RepositoryPolicyNotFoundException, "RepositoryPolicyNotFoundException");
var RepositoryPolicyNotFoundException = _RepositoryPolicyNotFoundException;
var ReplicationStatus = {
  COMPLETE: "COMPLETE",
  FAILED: "FAILED",
  IN_PROGRESS: "IN_PROGRESS"
};
var _ImageNotFoundException = class _ImageNotFoundException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "ImageNotFoundException",
      $fault: "client",
      ...opts
    });
    this.name = "ImageNotFoundException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _ImageNotFoundException.prototype);
  }
};
__name(_ImageNotFoundException, "ImageNotFoundException");
var ImageNotFoundException = _ImageNotFoundException;
var TagStatus = {
  ANY: "ANY",
  TAGGED: "TAGGED",
  UNTAGGED: "UNTAGGED"
};
var FindingSeverity = {
  CRITICAL: "CRITICAL",
  HIGH: "HIGH",
  INFORMATIONAL: "INFORMATIONAL",
  LOW: "LOW",
  MEDIUM: "MEDIUM",
  UNDEFINED: "UNDEFINED"
};
var ScanStatus = {
  ACTIVE: "ACTIVE",
  COMPLETE: "COMPLETE",
  FAILED: "FAILED",
  FINDINGS_UNAVAILABLE: "FINDINGS_UNAVAILABLE",
  IN_PROGRESS: "IN_PROGRESS",
  PENDING: "PENDING",
  SCAN_ELIGIBILITY_EXPIRED: "SCAN_ELIGIBILITY_EXPIRED",
  UNSUPPORTED_IMAGE: "UNSUPPORTED_IMAGE"
};
var _ScanNotFoundException = class _ScanNotFoundException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "ScanNotFoundException",
      $fault: "client",
      ...opts
    });
    this.name = "ScanNotFoundException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _ScanNotFoundException.prototype);
  }
};
__name(_ScanNotFoundException, "ScanNotFoundException");
var ScanNotFoundException = _ScanNotFoundException;
var RepositoryFilterType = {
  PREFIX_MATCH: "PREFIX_MATCH"
};
var _LayerInaccessibleException = class _LayerInaccessibleException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "LayerInaccessibleException",
      $fault: "client",
      ...opts
    });
    this.name = "LayerInaccessibleException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _LayerInaccessibleException.prototype);
  }
};
__name(_LayerInaccessibleException, "LayerInaccessibleException");
var LayerInaccessibleException = _LayerInaccessibleException;
var _LayersNotFoundException = class _LayersNotFoundException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "LayersNotFoundException",
      $fault: "client",
      ...opts
    });
    this.name = "LayersNotFoundException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _LayersNotFoundException.prototype);
  }
};
__name(_LayersNotFoundException, "LayersNotFoundException");
var LayersNotFoundException = _LayersNotFoundException;
var _UnableToGetUpstreamLayerException = class _UnableToGetUpstreamLayerException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "UnableToGetUpstreamLayerException",
      $fault: "client",
      ...opts
    });
    this.name = "UnableToGetUpstreamLayerException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _UnableToGetUpstreamLayerException.prototype);
  }
};
__name(_UnableToGetUpstreamLayerException, "UnableToGetUpstreamLayerException");
var UnableToGetUpstreamLayerException = _UnableToGetUpstreamLayerException;
var ImageActionType = {
  EXPIRE: "EXPIRE"
};
var LifecyclePolicyPreviewStatus = {
  COMPLETE: "COMPLETE",
  EXPIRED: "EXPIRED",
  FAILED: "FAILED",
  IN_PROGRESS: "IN_PROGRESS"
};
var _LifecyclePolicyPreviewNotFoundException = class _LifecyclePolicyPreviewNotFoundException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "LifecyclePolicyPreviewNotFoundException",
      $fault: "client",
      ...opts
    });
    this.name = "LifecyclePolicyPreviewNotFoundException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _LifecyclePolicyPreviewNotFoundException.prototype);
  }
};
__name(_LifecyclePolicyPreviewNotFoundException, "LifecyclePolicyPreviewNotFoundException");
var LifecyclePolicyPreviewNotFoundException = _LifecyclePolicyPreviewNotFoundException;
var ScanType = {
  BASIC: "BASIC",
  ENHANCED: "ENHANCED"
};
var _ImageAlreadyExistsException = class _ImageAlreadyExistsException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "ImageAlreadyExistsException",
      $fault: "client",
      ...opts
    });
    this.name = "ImageAlreadyExistsException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _ImageAlreadyExistsException.prototype);
  }
};
__name(_ImageAlreadyExistsException, "ImageAlreadyExistsException");
var ImageAlreadyExistsException = _ImageAlreadyExistsException;
var _ImageDigestDoesNotMatchException = class _ImageDigestDoesNotMatchException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "ImageDigestDoesNotMatchException",
      $fault: "client",
      ...opts
    });
    this.name = "ImageDigestDoesNotMatchException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _ImageDigestDoesNotMatchException.prototype);
  }
};
__name(_ImageDigestDoesNotMatchException, "ImageDigestDoesNotMatchException");
var ImageDigestDoesNotMatchException = _ImageDigestDoesNotMatchException;
var _ImageTagAlreadyExistsException = class _ImageTagAlreadyExistsException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "ImageTagAlreadyExistsException",
      $fault: "client",
      ...opts
    });
    this.name = "ImageTagAlreadyExistsException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _ImageTagAlreadyExistsException.prototype);
  }
};
__name(_ImageTagAlreadyExistsException, "ImageTagAlreadyExistsException");
var ImageTagAlreadyExistsException = _ImageTagAlreadyExistsException;
var _ReferencedImagesNotFoundException = class _ReferencedImagesNotFoundException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "ReferencedImagesNotFoundException",
      $fault: "client",
      ...opts
    });
    this.name = "ReferencedImagesNotFoundException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _ReferencedImagesNotFoundException.prototype);
  }
};
__name(_ReferencedImagesNotFoundException, "ReferencedImagesNotFoundException");
var ReferencedImagesNotFoundException = _ReferencedImagesNotFoundException;
var _UnsupportedImageTypeException = class _UnsupportedImageTypeException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "UnsupportedImageTypeException",
      $fault: "client",
      ...opts
    });
    this.name = "UnsupportedImageTypeException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _UnsupportedImageTypeException.prototype);
  }
};
__name(_UnsupportedImageTypeException, "UnsupportedImageTypeException");
var UnsupportedImageTypeException = _UnsupportedImageTypeException;
var _LifecyclePolicyPreviewInProgressException = class _LifecyclePolicyPreviewInProgressException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "LifecyclePolicyPreviewInProgressException",
      $fault: "client",
      ...opts
    });
    this.name = "LifecyclePolicyPreviewInProgressException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _LifecyclePolicyPreviewInProgressException.prototype);
  }
};
__name(_LifecyclePolicyPreviewInProgressException, "LifecyclePolicyPreviewInProgressException");
var LifecyclePolicyPreviewInProgressException = _LifecyclePolicyPreviewInProgressException;
var _InvalidLayerPartException = class _InvalidLayerPartException extends ECRServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "InvalidLayerPartException",
      $fault: "client",
      ...opts
    });
    this.name = "InvalidLayerPartException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _InvalidLayerPartException.prototype);
    this.registryId = opts.registryId;
    this.repositoryName = opts.repositoryName;
    this.uploadId = opts.uploadId;
    this.lastValidByteReceived = opts.lastValidByteReceived;
  }
};
__name(_InvalidLayerPartException, "InvalidLayerPartException");
var InvalidLayerPartException = _InvalidLayerPartException;

// src/protocols/Aws_json1_1.ts
var se_BatchCheckLayerAvailabilityCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("BatchCheckLayerAvailability");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_BatchCheckLayerAvailabilityCommand");
var se_BatchDeleteImageCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("BatchDeleteImage");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_BatchDeleteImageCommand");
var se_BatchGetImageCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("BatchGetImage");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_BatchGetImageCommand");
var se_BatchGetRepositoryScanningConfigurationCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("BatchGetRepositoryScanningConfiguration");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_BatchGetRepositoryScanningConfigurationCommand");
var se_CompleteLayerUploadCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("CompleteLayerUpload");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_CompleteLayerUploadCommand");
var se_CreatePullThroughCacheRuleCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("CreatePullThroughCacheRule");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_CreatePullThroughCacheRuleCommand");
var se_CreateRepositoryCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("CreateRepository");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_CreateRepositoryCommand");
var se_CreateRepositoryCreationTemplateCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("CreateRepositoryCreationTemplate");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_CreateRepositoryCreationTemplateCommand");
var se_DeleteLifecyclePolicyCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("DeleteLifecyclePolicy");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_DeleteLifecyclePolicyCommand");
var se_DeletePullThroughCacheRuleCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("DeletePullThroughCacheRule");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_DeletePullThroughCacheRuleCommand");
var se_DeleteRegistryPolicyCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("DeleteRegistryPolicy");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_DeleteRegistryPolicyCommand");
var se_DeleteRepositoryCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("DeleteRepository");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_DeleteRepositoryCommand");
var se_DeleteRepositoryCreationTemplateCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("DeleteRepositoryCreationTemplate");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_DeleteRepositoryCreationTemplateCommand");
var se_DeleteRepositoryPolicyCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("DeleteRepositoryPolicy");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_DeleteRepositoryPolicyCommand");
var se_DescribeImageReplicationStatusCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("DescribeImageReplicationStatus");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_DescribeImageReplicationStatusCommand");
var se_DescribeImagesCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("DescribeImages");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_DescribeImagesCommand");
var se_DescribeImageScanFindingsCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("DescribeImageScanFindings");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_DescribeImageScanFindingsCommand");
var se_DescribePullThroughCacheRulesCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("DescribePullThroughCacheRules");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_DescribePullThroughCacheRulesCommand");
var se_DescribeRegistryCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("DescribeRegistry");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_DescribeRegistryCommand");
var se_DescribeRepositoriesCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("DescribeRepositories");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_DescribeRepositoriesCommand");
var se_DescribeRepositoryCreationTemplatesCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("DescribeRepositoryCreationTemplates");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_DescribeRepositoryCreationTemplatesCommand");
var se_GetAuthorizationTokenCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("GetAuthorizationToken");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_GetAuthorizationTokenCommand");
var se_GetDownloadUrlForLayerCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("GetDownloadUrlForLayer");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_GetDownloadUrlForLayerCommand");
var se_GetLifecyclePolicyCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("GetLifecyclePolicy");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_GetLifecyclePolicyCommand");
var se_GetLifecyclePolicyPreviewCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("GetLifecyclePolicyPreview");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_GetLifecyclePolicyPreviewCommand");
var se_GetRegistryPolicyCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("GetRegistryPolicy");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_GetRegistryPolicyCommand");
var se_GetRegistryScanningConfigurationCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("GetRegistryScanningConfiguration");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_GetRegistryScanningConfigurationCommand");
var se_GetRepositoryPolicyCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("GetRepositoryPolicy");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_GetRepositoryPolicyCommand");
var se_InitiateLayerUploadCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("InitiateLayerUpload");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_InitiateLayerUploadCommand");
var se_ListImagesCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("ListImages");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_ListImagesCommand");
var se_ListTagsForResourceCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("ListTagsForResource");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_ListTagsForResourceCommand");
var se_PutImageCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("PutImage");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_PutImageCommand");
var se_PutImageScanningConfigurationCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("PutImageScanningConfiguration");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_PutImageScanningConfigurationCommand");
var se_PutImageTagMutabilityCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("PutImageTagMutability");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_PutImageTagMutabilityCommand");
var se_PutLifecyclePolicyCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("PutLifecyclePolicy");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_PutLifecyclePolicyCommand");
var se_PutRegistryPolicyCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("PutRegistryPolicy");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_PutRegistryPolicyCommand");
var se_PutRegistryScanningConfigurationCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("PutRegistryScanningConfiguration");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_PutRegistryScanningConfigurationCommand");
var se_PutReplicationConfigurationCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("PutReplicationConfiguration");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_PutReplicationConfigurationCommand");
var se_SetRepositoryPolicyCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("SetRepositoryPolicy");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_SetRepositoryPolicyCommand");
var se_StartImageScanCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("StartImageScan");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_StartImageScanCommand");
var se_StartLifecyclePolicyPreviewCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("StartLifecyclePolicyPreview");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_StartLifecyclePolicyPreviewCommand");
var se_TagResourceCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("TagResource");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_TagResourceCommand");
var se_UntagResourceCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("UntagResource");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_UntagResourceCommand");
var se_UpdatePullThroughCacheRuleCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("UpdatePullThroughCacheRule");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_UpdatePullThroughCacheRuleCommand");
var se_UpdateRepositoryCreationTemplateCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("UpdateRepositoryCreationTemplate");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_UpdateRepositoryCreationTemplateCommand");
var se_UploadLayerPartCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("UploadLayerPart");
  let body;
  body = JSON.stringify(se_UploadLayerPartRequest(input, context));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_UploadLayerPartCommand");
var se_ValidatePullThroughCacheRuleCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = sharedHeaders("ValidatePullThroughCacheRule");
  let body;
  body = JSON.stringify((0, import_smithy_client._json)(input));
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_ValidatePullThroughCacheRuleCommand");
var de_BatchCheckLayerAvailabilityCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = (0, import_smithy_client._json)(data);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_BatchCheckLayerAvailabilityCommand");
var de_BatchDeleteImageCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = (0, import_smithy_client._json)(data);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_BatchDeleteImageCommand");
var de_BatchGetImageCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = (0, import_smithy_client._json)(data);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_BatchGetImageCommand");
var de_BatchGetRepositoryScanningConfigurationCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = (0, import_smithy_client._json)(data);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_BatchGetRepositoryScanningConfigurationCommand");
var de_CompleteLayerUploadCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = (0, import_smithy_client._json)(data);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_CompleteLayerUploadCommand");
var de_CreatePullThroughCacheRuleCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = de_CreatePullThroughCacheRuleResponse(data, context);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_CreatePullThroughCacheRuleCommand");
var de_CreateRepositoryCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = de_CreateRepositoryResponse(data, context);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_CreateRepositoryCommand");
var de_CreateRepositoryCreationTemplateCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = de_CreateRepositoryCreationTemplateResponse(data, context);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_CreateRepositoryCreationTemplateCommand");
var de_DeleteLifecyclePolicyCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = de_DeleteLifecyclePolicyResponse(data, context);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_DeleteLifecyclePolicyCommand");
var de_DeletePullThroughCacheRuleCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = de_DeletePullThroughCacheRuleResponse(data, context);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_DeletePullThroughCacheRuleCommand");
var de_DeleteRegistryPolicyCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = (0, import_smithy_client._json)(data);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_DeleteRegistryPolicyCommand");
var de_DeleteRepositoryCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = de_DeleteRepositoryResponse(data, context);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_DeleteRepositoryCommand");
var de_DeleteRepositoryCreationTemplateCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = de_DeleteRepositoryCreationTemplateResponse(data, context);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_DeleteRepositoryCreationTemplateCommand");
var de_DeleteRepositoryPolicyCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = (0, import_smithy_client._json)(data);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_DeleteRepositoryPolicyCommand");
var de_DescribeImageReplicationStatusCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = (0, import_smithy_client._json)(data);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_DescribeImageReplicationStatusCommand");
var de_DescribeImagesCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = de_DescribeImagesResponse(data, context);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_DescribeImagesCommand");
var de_DescribeImageScanFindingsCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = de_DescribeImageScanFindingsResponse(data, context);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_DescribeImageScanFindingsCommand");
var de_DescribePullThroughCacheRulesCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = de_DescribePullThroughCacheRulesResponse(data, context);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_DescribePullThroughCacheRulesCommand");
var de_DescribeRegistryCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = (0, import_smithy_client._json)(data);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_DescribeRegistryCommand");
var de_DescribeRepositoriesCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = de_DescribeRepositoriesResponse(data, context);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_DescribeRepositoriesCommand");
var de_DescribeRepositoryCreationTemplatesCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = de_DescribeRepositoryCreationTemplatesResponse(data, context);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_DescribeRepositoryCreationTemplatesCommand");
var de_GetAuthorizationTokenCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = de_GetAuthorizationTokenResponse(data, context);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_GetAuthorizationTokenCommand");
var de_GetDownloadUrlForLayerCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = (0, import_smithy_client._json)(data);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_GetDownloadUrlForLayerCommand");
var de_GetLifecyclePolicyCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = de_GetLifecyclePolicyResponse(data, context);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_GetLifecyclePolicyCommand");
var de_GetLifecyclePolicyPreviewCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = de_GetLifecyclePolicyPreviewResponse(data, context);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_GetLifecyclePolicyPreviewCommand");
var de_GetRegistryPolicyCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = (0, import_smithy_client._json)(data);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_GetRegistryPolicyCommand");
var de_GetRegistryScanningConfigurationCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = (0, import_smithy_client._json)(data);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_GetRegistryScanningConfigurationCommand");
var de_GetRepositoryPolicyCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = (0, import_smithy_client._json)(data);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_GetRepositoryPolicyCommand");
var de_InitiateLayerUploadCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = (0, import_smithy_client._json)(data);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_InitiateLayerUploadCommand");
var de_ListImagesCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = (0, import_smithy_client._json)(data);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_ListImagesCommand");
var de_ListTagsForResourceCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = (0, import_smithy_client._json)(data);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_ListTagsForResourceCommand");
var de_PutImageCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = (0, import_smithy_client._json)(data);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_PutImageCommand");
var de_PutImageScanningConfigurationCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = (0, import_smithy_client._json)(data);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_PutImageScanningConfigurationCommand");
var de_PutImageTagMutabilityCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = (0, import_smithy_client._json)(data);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_PutImageTagMutabilityCommand");
var de_PutLifecyclePolicyCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = (0, import_smithy_client._json)(data);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_PutLifecyclePolicyCommand");
var de_PutRegistryPolicyCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = (0, import_smithy_client._json)(data);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_PutRegistryPolicyCommand");
var de_PutRegistryScanningConfigurationCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = (0, import_smithy_client._json)(data);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_PutRegistryScanningConfigurationCommand");
var de_PutReplicationConfigurationCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = (0, import_smithy_client._json)(data);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_PutReplicationConfigurationCommand");
var de_SetRepositoryPolicyCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = (0, import_smithy_client._json)(data);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_SetRepositoryPolicyCommand");
var de_StartImageScanCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = (0, import_smithy_client._json)(data);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_StartImageScanCommand");
var de_StartLifecyclePolicyPreviewCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = (0, import_smithy_client._json)(data);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_StartLifecyclePolicyPreviewCommand");
var de_TagResourceCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = (0, import_smithy_client._json)(data);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_TagResourceCommand");
var de_UntagResourceCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = (0, import_smithy_client._json)(data);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_UntagResourceCommand");
var de_UpdatePullThroughCacheRuleCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = de_UpdatePullThroughCacheRuleResponse(data, context);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_UpdatePullThroughCacheRuleCommand");
var de_UpdateRepositoryCreationTemplateCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = de_UpdateRepositoryCreationTemplateResponse(data, context);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_UpdateRepositoryCreationTemplateCommand");
var de_UploadLayerPartCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = (0, import_smithy_client._json)(data);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_UploadLayerPartCommand");
var de_ValidatePullThroughCacheRuleCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core2.parseJsonBody)(output.body, context);
  let contents = {};
  contents = (0, import_smithy_client._json)(data);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_ValidatePullThroughCacheRuleCommand");
var de_CommandError = /* @__PURE__ */ __name(async (output, context) => {
  const parsedOutput = {
    ...output,
    body: await (0, import_core2.parseJsonErrorBody)(output.body, context)
  };
  const errorCode = (0, import_core2.loadRestJsonErrorCode)(output, parsedOutput.body);
  switch (errorCode) {
    case "InvalidParameterException":
    case "com.amazonaws.ecr#InvalidParameterException":
      throw await de_InvalidParameterExceptionRes(parsedOutput, context);
    case "RepositoryNotFoundException":
    case "com.amazonaws.ecr#RepositoryNotFoundException":
      throw await de_RepositoryNotFoundExceptionRes(parsedOutput, context);
    case "ServerException":
    case "com.amazonaws.ecr#ServerException":
      throw await de_ServerExceptionRes(parsedOutput, context);
    case "LimitExceededException":
    case "com.amazonaws.ecr#LimitExceededException":
      throw await de_LimitExceededExceptionRes(parsedOutput, context);
    case "UnableToGetUpstreamImageException":
    case "com.amazonaws.ecr#UnableToGetUpstreamImageException":
      throw await de_UnableToGetUpstreamImageExceptionRes(parsedOutput, context);
    case "ValidationException":
    case "com.amazonaws.ecr#ValidationException":
      throw await de_ValidationExceptionRes(parsedOutput, context);
    case "EmptyUploadException":
    case "com.amazonaws.ecr#EmptyUploadException":
      throw await de_EmptyUploadExceptionRes(parsedOutput, context);
    case "InvalidLayerException":
    case "com.amazonaws.ecr#InvalidLayerException":
      throw await de_InvalidLayerExceptionRes(parsedOutput, context);
    case "KmsException":
    case "com.amazonaws.ecr#KmsException":
      throw await de_KmsExceptionRes(parsedOutput, context);
    case "LayerAlreadyExistsException":
    case "com.amazonaws.ecr#LayerAlreadyExistsException":
      throw await de_LayerAlreadyExistsExceptionRes(parsedOutput, context);
    case "LayerPartTooSmallException":
    case "com.amazonaws.ecr#LayerPartTooSmallException":
      throw await de_LayerPartTooSmallExceptionRes(parsedOutput, context);
    case "UploadNotFoundException":
    case "com.amazonaws.ecr#UploadNotFoundException":
      throw await de_UploadNotFoundExceptionRes(parsedOutput, context);
    case "PullThroughCacheRuleAlreadyExistsException":
    case "com.amazonaws.ecr#PullThroughCacheRuleAlreadyExistsException":
      throw await de_PullThroughCacheRuleAlreadyExistsExceptionRes(parsedOutput, context);
    case "SecretNotFoundException":
    case "com.amazonaws.ecr#SecretNotFoundException":
      throw await de_SecretNotFoundExceptionRes(parsedOutput, context);
    case "UnableToAccessSecretException":
    case "com.amazonaws.ecr#UnableToAccessSecretException":
      throw await de_UnableToAccessSecretExceptionRes(parsedOutput, context);
    case "UnableToDecryptSecretValueException":
    case "com.amazonaws.ecr#UnableToDecryptSecretValueException":
      throw await de_UnableToDecryptSecretValueExceptionRes(parsedOutput, context);
    case "UnsupportedUpstreamRegistryException":
    case "com.amazonaws.ecr#UnsupportedUpstreamRegistryException":
      throw await de_UnsupportedUpstreamRegistryExceptionRes(parsedOutput, context);
    case "InvalidTagParameterException":
    case "com.amazonaws.ecr#InvalidTagParameterException":
      throw await de_InvalidTagParameterExceptionRes(parsedOutput, context);
    case "RepositoryAlreadyExistsException":
    case "com.amazonaws.ecr#RepositoryAlreadyExistsException":
      throw await de_RepositoryAlreadyExistsExceptionRes(parsedOutput, context);
    case "TooManyTagsException":
    case "com.amazonaws.ecr#TooManyTagsException":
      throw await de_TooManyTagsExceptionRes(parsedOutput, context);
    case "TemplateAlreadyExistsException":
    case "com.amazonaws.ecr#TemplateAlreadyExistsException":
      throw await de_TemplateAlreadyExistsExceptionRes(parsedOutput, context);
    case "LifecyclePolicyNotFoundException":
    case "com.amazonaws.ecr#LifecyclePolicyNotFoundException":
      throw await de_LifecyclePolicyNotFoundExceptionRes(parsedOutput, context);
    case "PullThroughCacheRuleNotFoundException":
    case "com.amazonaws.ecr#PullThroughCacheRuleNotFoundException":
      throw await de_PullThroughCacheRuleNotFoundExceptionRes(parsedOutput, context);
    case "RegistryPolicyNotFoundException":
    case "com.amazonaws.ecr#RegistryPolicyNotFoundException":
      throw await de_RegistryPolicyNotFoundExceptionRes(parsedOutput, context);
    case "RepositoryNotEmptyException":
    case "com.amazonaws.ecr#RepositoryNotEmptyException":
      throw await de_RepositoryNotEmptyExceptionRes(parsedOutput, context);
    case "TemplateNotFoundException":
    case "com.amazonaws.ecr#TemplateNotFoundException":
      throw await de_TemplateNotFoundExceptionRes(parsedOutput, context);
    case "RepositoryPolicyNotFoundException":
    case "com.amazonaws.ecr#RepositoryPolicyNotFoundException":
      throw await de_RepositoryPolicyNotFoundExceptionRes(parsedOutput, context);
    case "ImageNotFoundException":
    case "com.amazonaws.ecr#ImageNotFoundException":
      throw await de_ImageNotFoundExceptionRes(parsedOutput, context);
    case "ScanNotFoundException":
    case "com.amazonaws.ecr#ScanNotFoundException":
      throw await de_ScanNotFoundExceptionRes(parsedOutput, context);
    case "LayerInaccessibleException":
    case "com.amazonaws.ecr#LayerInaccessibleException":
      throw await de_LayerInaccessibleExceptionRes(parsedOutput, context);
    case "LayersNotFoundException":
    case "com.amazonaws.ecr#LayersNotFoundException":
      throw await de_LayersNotFoundExceptionRes(parsedOutput, context);
    case "UnableToGetUpstreamLayerException":
    case "com.amazonaws.ecr#UnableToGetUpstreamLayerException":
      throw await de_UnableToGetUpstreamLayerExceptionRes(parsedOutput, context);
    case "LifecyclePolicyPreviewNotFoundException":
    case "com.amazonaws.ecr#LifecyclePolicyPreviewNotFoundException":
      throw await de_LifecyclePolicyPreviewNotFoundExceptionRes(parsedOutput, context);
    case "ImageAlreadyExistsException":
    case "com.amazonaws.ecr#ImageAlreadyExistsException":
      throw await de_ImageAlreadyExistsExceptionRes(parsedOutput, context);
    case "ImageDigestDoesNotMatchException":
    case "com.amazonaws.ecr#ImageDigestDoesNotMatchException":
      throw await de_ImageDigestDoesNotMatchExceptionRes(parsedOutput, context);
    case "ImageTagAlreadyExistsException":
    case "com.amazonaws.ecr#ImageTagAlreadyExistsException":
      throw await de_ImageTagAlreadyExistsExceptionRes(parsedOutput, context);
    case "ReferencedImagesNotFoundException":
    case "com.amazonaws.ecr#ReferencedImagesNotFoundException":
      throw await de_ReferencedImagesNotFoundExceptionRes(parsedOutput, context);
    case "UnsupportedImageTypeException":
    case "com.amazonaws.ecr#UnsupportedImageTypeException":
      throw await de_UnsupportedImageTypeExceptionRes(parsedOutput, context);
    case "LifecyclePolicyPreviewInProgressException":
    case "com.amazonaws.ecr#LifecyclePolicyPreviewInProgressException":
      throw await de_LifecyclePolicyPreviewInProgressExceptionRes(parsedOutput, context);
    case "InvalidLayerPartException":
    case "com.amazonaws.ecr#InvalidLayerPartException":
      throw await de_InvalidLayerPartExceptionRes(parsedOutput, context);
    default:
      const parsedBody = parsedOutput.body;
      return throwDefaultError({
        output,
        parsedBody,
        errorCode
      });
  }
}, "de_CommandError");
var de_EmptyUploadExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new EmptyUploadException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_EmptyUploadExceptionRes");
var de_ImageAlreadyExistsExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new ImageAlreadyExistsException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_ImageAlreadyExistsExceptionRes");
var de_ImageDigestDoesNotMatchExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new ImageDigestDoesNotMatchException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_ImageDigestDoesNotMatchExceptionRes");
var de_ImageNotFoundExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new ImageNotFoundException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_ImageNotFoundExceptionRes");
var de_ImageTagAlreadyExistsExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new ImageTagAlreadyExistsException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_ImageTagAlreadyExistsExceptionRes");
var de_InvalidLayerExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new InvalidLayerException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_InvalidLayerExceptionRes");
var de_InvalidLayerPartExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new InvalidLayerPartException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_InvalidLayerPartExceptionRes");
var de_InvalidParameterExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new InvalidParameterException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_InvalidParameterExceptionRes");
var de_InvalidTagParameterExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new InvalidTagParameterException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_InvalidTagParameterExceptionRes");
var de_KmsExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new KmsException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_KmsExceptionRes");
var de_LayerAlreadyExistsExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new LayerAlreadyExistsException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_LayerAlreadyExistsExceptionRes");
var de_LayerInaccessibleExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new LayerInaccessibleException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_LayerInaccessibleExceptionRes");
var de_LayerPartTooSmallExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new LayerPartTooSmallException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_LayerPartTooSmallExceptionRes");
var de_LayersNotFoundExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new LayersNotFoundException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_LayersNotFoundExceptionRes");
var de_LifecyclePolicyNotFoundExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new LifecyclePolicyNotFoundException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_LifecyclePolicyNotFoundExceptionRes");
var de_LifecyclePolicyPreviewInProgressExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new LifecyclePolicyPreviewInProgressException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_LifecyclePolicyPreviewInProgressExceptionRes");
var de_LifecyclePolicyPreviewNotFoundExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new LifecyclePolicyPreviewNotFoundException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_LifecyclePolicyPreviewNotFoundExceptionRes");
var de_LimitExceededExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new LimitExceededException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_LimitExceededExceptionRes");
var de_PullThroughCacheRuleAlreadyExistsExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new PullThroughCacheRuleAlreadyExistsException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_PullThroughCacheRuleAlreadyExistsExceptionRes");
var de_PullThroughCacheRuleNotFoundExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new PullThroughCacheRuleNotFoundException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_PullThroughCacheRuleNotFoundExceptionRes");
var de_ReferencedImagesNotFoundExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new ReferencedImagesNotFoundException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_ReferencedImagesNotFoundExceptionRes");
var de_RegistryPolicyNotFoundExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new RegistryPolicyNotFoundException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_RegistryPolicyNotFoundExceptionRes");
var de_RepositoryAlreadyExistsExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new RepositoryAlreadyExistsException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_RepositoryAlreadyExistsExceptionRes");
var de_RepositoryNotEmptyExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new RepositoryNotEmptyException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_RepositoryNotEmptyExceptionRes");
var de_RepositoryNotFoundExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new RepositoryNotFoundException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_RepositoryNotFoundExceptionRes");
var de_RepositoryPolicyNotFoundExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new RepositoryPolicyNotFoundException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_RepositoryPolicyNotFoundExceptionRes");
var de_ScanNotFoundExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new ScanNotFoundException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_ScanNotFoundExceptionRes");
var de_SecretNotFoundExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new SecretNotFoundException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_SecretNotFoundExceptionRes");
var de_ServerExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new ServerException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_ServerExceptionRes");
var de_TemplateAlreadyExistsExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new TemplateAlreadyExistsException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_TemplateAlreadyExistsExceptionRes");
var de_TemplateNotFoundExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new TemplateNotFoundException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_TemplateNotFoundExceptionRes");
var de_TooManyTagsExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new TooManyTagsException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_TooManyTagsExceptionRes");
var de_UnableToAccessSecretExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new UnableToAccessSecretException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_UnableToAccessSecretExceptionRes");
var de_UnableToDecryptSecretValueExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new UnableToDecryptSecretValueException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_UnableToDecryptSecretValueExceptionRes");
var de_UnableToGetUpstreamImageExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new UnableToGetUpstreamImageException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_UnableToGetUpstreamImageExceptionRes");
var de_UnableToGetUpstreamLayerExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new UnableToGetUpstreamLayerException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_UnableToGetUpstreamLayerExceptionRes");
var de_UnsupportedImageTypeExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new UnsupportedImageTypeException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_UnsupportedImageTypeExceptionRes");
var de_UnsupportedUpstreamRegistryExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new UnsupportedUpstreamRegistryException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_UnsupportedUpstreamRegistryExceptionRes");
var de_UploadNotFoundExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new UploadNotFoundException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_UploadNotFoundExceptionRes");
var de_ValidationExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = (0, import_smithy_client._json)(body);
  const exception = new ValidationException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_ValidationExceptionRes");
var se_UploadLayerPartRequest = /* @__PURE__ */ __name((input, context) => {
  return (0, import_smithy_client.take)(input, {
    layerPartBlob: context.base64Encoder,
    partFirstByte: [],
    partLastByte: [],
    registryId: [],
    repositoryName: [],
    uploadId: []
  });
}, "se_UploadLayerPartRequest");
var de_AuthorizationData = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    authorizationToken: import_smithy_client.expectString,
    expiresAt: (_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))),
    proxyEndpoint: import_smithy_client.expectString
  });
}, "de_AuthorizationData");
var de_AuthorizationDataList = /* @__PURE__ */ __name((output, context) => {
  const retVal = (output || []).filter((e) => e != null).map((entry) => {
    return de_AuthorizationData(entry, context);
  });
  return retVal;
}, "de_AuthorizationDataList");
var de_AwsEcrContainerImageDetails = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    architecture: import_smithy_client.expectString,
    author: import_smithy_client.expectString,
    imageHash: import_smithy_client.expectString,
    imageTags: import_smithy_client._json,
    platform: import_smithy_client.expectString,
    pushedAt: (_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))),
    registry: import_smithy_client.expectString,
    repositoryName: import_smithy_client.expectString
  });
}, "de_AwsEcrContainerImageDetails");
var de_CreatePullThroughCacheRuleResponse = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    createdAt: (_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))),
    credentialArn: import_smithy_client.expectString,
    ecrRepositoryPrefix: import_smithy_client.expectString,
    registryId: import_smithy_client.expectString,
    upstreamRegistry: import_smithy_client.expectString,
    upstreamRegistryUrl: import_smithy_client.expectString
  });
}, "de_CreatePullThroughCacheRuleResponse");
var de_CreateRepositoryCreationTemplateResponse = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    registryId: import_smithy_client.expectString,
    repositoryCreationTemplate: (_) => de_RepositoryCreationTemplate(_, context)
  });
}, "de_CreateRepositoryCreationTemplateResponse");
var de_CreateRepositoryResponse = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    repository: (_) => de_Repository(_, context)
  });
}, "de_CreateRepositoryResponse");
var de_CvssScore = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    baseScore: import_smithy_client.limitedParseDouble,
    scoringVector: import_smithy_client.expectString,
    source: import_smithy_client.expectString,
    version: import_smithy_client.expectString
  });
}, "de_CvssScore");
var de_CvssScoreDetails = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    adjustments: import_smithy_client._json,
    score: import_smithy_client.limitedParseDouble,
    scoreSource: import_smithy_client.expectString,
    scoringVector: import_smithy_client.expectString,
    version: import_smithy_client.expectString
  });
}, "de_CvssScoreDetails");
var de_CvssScoreList = /* @__PURE__ */ __name((output, context) => {
  const retVal = (output || []).filter((e) => e != null).map((entry) => {
    return de_CvssScore(entry, context);
  });
  return retVal;
}, "de_CvssScoreList");
var de_DeleteLifecyclePolicyResponse = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    lastEvaluatedAt: (_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))),
    lifecyclePolicyText: import_smithy_client.expectString,
    registryId: import_smithy_client.expectString,
    repositoryName: import_smithy_client.expectString
  });
}, "de_DeleteLifecyclePolicyResponse");
var de_DeletePullThroughCacheRuleResponse = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    createdAt: (_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))),
    credentialArn: import_smithy_client.expectString,
    ecrRepositoryPrefix: import_smithy_client.expectString,
    registryId: import_smithy_client.expectString,
    upstreamRegistryUrl: import_smithy_client.expectString
  });
}, "de_DeletePullThroughCacheRuleResponse");
var de_DeleteRepositoryCreationTemplateResponse = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    registryId: import_smithy_client.expectString,
    repositoryCreationTemplate: (_) => de_RepositoryCreationTemplate(_, context)
  });
}, "de_DeleteRepositoryCreationTemplateResponse");
var de_DeleteRepositoryResponse = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    repository: (_) => de_Repository(_, context)
  });
}, "de_DeleteRepositoryResponse");
var de_DescribeImageScanFindingsResponse = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    imageId: import_smithy_client._json,
    imageScanFindings: (_) => de_ImageScanFindings(_, context),
    imageScanStatus: import_smithy_client._json,
    nextToken: import_smithy_client.expectString,
    registryId: import_smithy_client.expectString,
    repositoryName: import_smithy_client.expectString
  });
}, "de_DescribeImageScanFindingsResponse");
var de_DescribeImagesResponse = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    imageDetails: (_) => de_ImageDetailList(_, context),
    nextToken: import_smithy_client.expectString
  });
}, "de_DescribeImagesResponse");
var de_DescribePullThroughCacheRulesResponse = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    nextToken: import_smithy_client.expectString,
    pullThroughCacheRules: (_) => de_PullThroughCacheRuleList(_, context)
  });
}, "de_DescribePullThroughCacheRulesResponse");
var de_DescribeRepositoriesResponse = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    nextToken: import_smithy_client.expectString,
    repositories: (_) => de_RepositoryList(_, context)
  });
}, "de_DescribeRepositoriesResponse");
var de_DescribeRepositoryCreationTemplatesResponse = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    nextToken: import_smithy_client.expectString,
    registryId: import_smithy_client.expectString,
    repositoryCreationTemplates: (_) => de_RepositoryCreationTemplateList(_, context)
  });
}, "de_DescribeRepositoryCreationTemplatesResponse");
var de_EnhancedImageScanFinding = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    awsAccountId: import_smithy_client.expectString,
    description: import_smithy_client.expectString,
    findingArn: import_smithy_client.expectString,
    firstObservedAt: (_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))),
    lastObservedAt: (_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))),
    packageVulnerabilityDetails: (_) => de_PackageVulnerabilityDetails(_, context),
    remediation: import_smithy_client._json,
    resources: (_) => de_ResourceList(_, context),
    score: import_smithy_client.limitedParseDouble,
    scoreDetails: (_) => de_ScoreDetails(_, context),
    severity: import_smithy_client.expectString,
    status: import_smithy_client.expectString,
    title: import_smithy_client.expectString,
    type: import_smithy_client.expectString,
    updatedAt: (_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_)))
  });
}, "de_EnhancedImageScanFinding");
var de_EnhancedImageScanFindingList = /* @__PURE__ */ __name((output, context) => {
  const retVal = (output || []).filter((e) => e != null).map((entry) => {
    return de_EnhancedImageScanFinding(entry, context);
  });
  return retVal;
}, "de_EnhancedImageScanFindingList");
var de_GetAuthorizationTokenResponse = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    authorizationData: (_) => de_AuthorizationDataList(_, context)
  });
}, "de_GetAuthorizationTokenResponse");
var de_GetLifecyclePolicyPreviewResponse = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    lifecyclePolicyText: import_smithy_client.expectString,
    nextToken: import_smithy_client.expectString,
    previewResults: (_) => de_LifecyclePolicyPreviewResultList(_, context),
    registryId: import_smithy_client.expectString,
    repositoryName: import_smithy_client.expectString,
    status: import_smithy_client.expectString,
    summary: import_smithy_client._json
  });
}, "de_GetLifecyclePolicyPreviewResponse");
var de_GetLifecyclePolicyResponse = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    lastEvaluatedAt: (_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))),
    lifecyclePolicyText: import_smithy_client.expectString,
    registryId: import_smithy_client.expectString,
    repositoryName: import_smithy_client.expectString
  });
}, "de_GetLifecyclePolicyResponse");
var de_ImageDetail = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    artifactMediaType: import_smithy_client.expectString,
    imageDigest: import_smithy_client.expectString,
    imageManifestMediaType: import_smithy_client.expectString,
    imagePushedAt: (_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))),
    imageScanFindingsSummary: (_) => de_ImageScanFindingsSummary(_, context),
    imageScanStatus: import_smithy_client._json,
    imageSizeInBytes: import_smithy_client.expectLong,
    imageTags: import_smithy_client._json,
    lastRecordedPullTime: (_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))),
    registryId: import_smithy_client.expectString,
    repositoryName: import_smithy_client.expectString
  });
}, "de_ImageDetail");
var de_ImageDetailList = /* @__PURE__ */ __name((output, context) => {
  const retVal = (output || []).filter((e) => e != null).map((entry) => {
    return de_ImageDetail(entry, context);
  });
  return retVal;
}, "de_ImageDetailList");
var de_ImageScanFindings = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    enhancedFindings: (_) => de_EnhancedImageScanFindingList(_, context),
    findingSeverityCounts: import_smithy_client._json,
    findings: import_smithy_client._json,
    imageScanCompletedAt: (_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))),
    vulnerabilitySourceUpdatedAt: (_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_)))
  });
}, "de_ImageScanFindings");
var de_ImageScanFindingsSummary = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    findingSeverityCounts: import_smithy_client._json,
    imageScanCompletedAt: (_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))),
    vulnerabilitySourceUpdatedAt: (_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_)))
  });
}, "de_ImageScanFindingsSummary");
var de_LifecyclePolicyPreviewResult = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    action: import_smithy_client._json,
    appliedRulePriority: import_smithy_client.expectInt32,
    imageDigest: import_smithy_client.expectString,
    imagePushedAt: (_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))),
    imageTags: import_smithy_client._json
  });
}, "de_LifecyclePolicyPreviewResult");
var de_LifecyclePolicyPreviewResultList = /* @__PURE__ */ __name((output, context) => {
  const retVal = (output || []).filter((e) => e != null).map((entry) => {
    return de_LifecyclePolicyPreviewResult(entry, context);
  });
  return retVal;
}, "de_LifecyclePolicyPreviewResultList");
var de_PackageVulnerabilityDetails = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    cvss: (_) => de_CvssScoreList(_, context),
    referenceUrls: import_smithy_client._json,
    relatedVulnerabilities: import_smithy_client._json,
    source: import_smithy_client.expectString,
    sourceUrl: import_smithy_client.expectString,
    vendorCreatedAt: (_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))),
    vendorSeverity: import_smithy_client.expectString,
    vendorUpdatedAt: (_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))),
    vulnerabilityId: import_smithy_client.expectString,
    vulnerablePackages: import_smithy_client._json
  });
}, "de_PackageVulnerabilityDetails");
var de_PullThroughCacheRule = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    createdAt: (_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))),
    credentialArn: import_smithy_client.expectString,
    ecrRepositoryPrefix: import_smithy_client.expectString,
    registryId: import_smithy_client.expectString,
    updatedAt: (_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))),
    upstreamRegistry: import_smithy_client.expectString,
    upstreamRegistryUrl: import_smithy_client.expectString
  });
}, "de_PullThroughCacheRule");
var de_PullThroughCacheRuleList = /* @__PURE__ */ __name((output, context) => {
  const retVal = (output || []).filter((e) => e != null).map((entry) => {
    return de_PullThroughCacheRule(entry, context);
  });
  return retVal;
}, "de_PullThroughCacheRuleList");
var de_Repository = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    createdAt: (_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))),
    encryptionConfiguration: import_smithy_client._json,
    imageScanningConfiguration: import_smithy_client._json,
    imageTagMutability: import_smithy_client.expectString,
    registryId: import_smithy_client.expectString,
    repositoryArn: import_smithy_client.expectString,
    repositoryName: import_smithy_client.expectString,
    repositoryUri: import_smithy_client.expectString
  });
}, "de_Repository");
var de_RepositoryCreationTemplate = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    appliedFor: import_smithy_client._json,
    createdAt: (_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_))),
    customRoleArn: import_smithy_client.expectString,
    description: import_smithy_client.expectString,
    encryptionConfiguration: import_smithy_client._json,
    imageTagMutability: import_smithy_client.expectString,
    lifecyclePolicy: import_smithy_client.expectString,
    prefix: import_smithy_client.expectString,
    repositoryPolicy: import_smithy_client.expectString,
    resourceTags: import_smithy_client._json,
    updatedAt: (_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_)))
  });
}, "de_RepositoryCreationTemplate");
var de_RepositoryCreationTemplateList = /* @__PURE__ */ __name((output, context) => {
  const retVal = (output || []).filter((e) => e != null).map((entry) => {
    return de_RepositoryCreationTemplate(entry, context);
  });
  return retVal;
}, "de_RepositoryCreationTemplateList");
var de_RepositoryList = /* @__PURE__ */ __name((output, context) => {
  const retVal = (output || []).filter((e) => e != null).map((entry) => {
    return de_Repository(entry, context);
  });
  return retVal;
}, "de_RepositoryList");
var de_Resource = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    details: (_) => de_ResourceDetails(_, context),
    id: import_smithy_client.expectString,
    tags: import_smithy_client._json,
    type: import_smithy_client.expectString
  });
}, "de_Resource");
var de_ResourceDetails = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    awsEcrContainerImage: (_) => de_AwsEcrContainerImageDetails(_, context)
  });
}, "de_ResourceDetails");
var de_ResourceList = /* @__PURE__ */ __name((output, context) => {
  const retVal = (output || []).filter((e) => e != null).map((entry) => {
    return de_Resource(entry, context);
  });
  return retVal;
}, "de_ResourceList");
var de_ScoreDetails = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    cvss: (_) => de_CvssScoreDetails(_, context)
  });
}, "de_ScoreDetails");
var de_UpdatePullThroughCacheRuleResponse = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    credentialArn: import_smithy_client.expectString,
    ecrRepositoryPrefix: import_smithy_client.expectString,
    registryId: import_smithy_client.expectString,
    updatedAt: (_) => (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseEpochTimestamp)((0, import_smithy_client.expectNumber)(_)))
  });
}, "de_UpdatePullThroughCacheRuleResponse");
var de_UpdateRepositoryCreationTemplateResponse = /* @__PURE__ */ __name((output, context) => {
  return (0, import_smithy_client.take)(output, {
    registryId: import_smithy_client.expectString,
    repositoryCreationTemplate: (_) => de_RepositoryCreationTemplate(_, context)
  });
}, "de_UpdateRepositoryCreationTemplateResponse");
var deserializeMetadata = /* @__PURE__ */ __name((output) => ({
  httpStatusCode: output.statusCode,
  requestId: output.headers["x-amzn-requestid"] ?? output.headers["x-amzn-request-id"] ?? output.headers["x-amz-request-id"],
  extendedRequestId: output.headers["x-amz-id-2"],
  cfId: output.headers["x-amz-cf-id"]
}), "deserializeMetadata");
var throwDefaultError = (0, import_smithy_client.withBaseException)(ECRServiceException);
var buildHttpRpcRequest = /* @__PURE__ */ __name(async (context, headers, path, resolvedHostname, body) => {
  const { hostname, protocol = "https", port, path: basePath } = await context.endpoint();
  const contents = {
    protocol,
    hostname,
    port,
    method: "POST",
    path: basePath.endsWith("/") ? basePath.slice(0, -1) + path : basePath + path,
    headers
  };
  if (resolvedHostname !== void 0) {
    contents.hostname = resolvedHostname;
  }
  if (body !== void 0) {
    contents.body = body;
  }
  return new import_protocol_http.HttpRequest(contents);
}, "buildHttpRpcRequest");
function sharedHeaders(operation) {
  return {
    "content-type": "application/x-amz-json-1.1",
    "x-amz-target": `AmazonEC2ContainerRegistry_V20150921.${operation}`
  };
}
__name(sharedHeaders, "sharedHeaders");

// src/commands/BatchCheckLayerAvailabilityCommand.ts
var _BatchCheckLayerAvailabilityCommand = class _BatchCheckLayerAvailabilityCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "BatchCheckLayerAvailability", {}).n("ECRClient", "BatchCheckLayerAvailabilityCommand").f(void 0, void 0).ser(se_BatchCheckLayerAvailabilityCommand).de(de_BatchCheckLayerAvailabilityCommand).build() {
};
__name(_BatchCheckLayerAvailabilityCommand, "BatchCheckLayerAvailabilityCommand");
var BatchCheckLayerAvailabilityCommand = _BatchCheckLayerAvailabilityCommand;

// src/commands/BatchDeleteImageCommand.ts



var _BatchDeleteImageCommand = class _BatchDeleteImageCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "BatchDeleteImage", {}).n("ECRClient", "BatchDeleteImageCommand").f(void 0, void 0).ser(se_BatchDeleteImageCommand).de(de_BatchDeleteImageCommand).build() {
};
__name(_BatchDeleteImageCommand, "BatchDeleteImageCommand");
var BatchDeleteImageCommand = _BatchDeleteImageCommand;

// src/commands/BatchGetImageCommand.ts



var _BatchGetImageCommand = class _BatchGetImageCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "BatchGetImage", {}).n("ECRClient", "BatchGetImageCommand").f(void 0, void 0).ser(se_BatchGetImageCommand).de(de_BatchGetImageCommand).build() {
};
__name(_BatchGetImageCommand, "BatchGetImageCommand");
var BatchGetImageCommand = _BatchGetImageCommand;

// src/commands/BatchGetRepositoryScanningConfigurationCommand.ts



var _BatchGetRepositoryScanningConfigurationCommand = class _BatchGetRepositoryScanningConfigurationCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "BatchGetRepositoryScanningConfiguration", {}).n("ECRClient", "BatchGetRepositoryScanningConfigurationCommand").f(void 0, void 0).ser(se_BatchGetRepositoryScanningConfigurationCommand).de(de_BatchGetRepositoryScanningConfigurationCommand).build() {
};
__name(_BatchGetRepositoryScanningConfigurationCommand, "BatchGetRepositoryScanningConfigurationCommand");
var BatchGetRepositoryScanningConfigurationCommand = _BatchGetRepositoryScanningConfigurationCommand;

// src/commands/CompleteLayerUploadCommand.ts



var _CompleteLayerUploadCommand = class _CompleteLayerUploadCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "CompleteLayerUpload", {}).n("ECRClient", "CompleteLayerUploadCommand").f(void 0, void 0).ser(se_CompleteLayerUploadCommand).de(de_CompleteLayerUploadCommand).build() {
};
__name(_CompleteLayerUploadCommand, "CompleteLayerUploadCommand");
var CompleteLayerUploadCommand = _CompleteLayerUploadCommand;

// src/commands/CreatePullThroughCacheRuleCommand.ts



var _CreatePullThroughCacheRuleCommand = class _CreatePullThroughCacheRuleCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "CreatePullThroughCacheRule", {}).n("ECRClient", "CreatePullThroughCacheRuleCommand").f(void 0, void 0).ser(se_CreatePullThroughCacheRuleCommand).de(de_CreatePullThroughCacheRuleCommand).build() {
};
__name(_CreatePullThroughCacheRuleCommand, "CreatePullThroughCacheRuleCommand");
var CreatePullThroughCacheRuleCommand = _CreatePullThroughCacheRuleCommand;

// src/commands/CreateRepositoryCommand.ts



var _CreateRepositoryCommand = class _CreateRepositoryCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "CreateRepository", {}).n("ECRClient", "CreateRepositoryCommand").f(void 0, void 0).ser(se_CreateRepositoryCommand).de(de_CreateRepositoryCommand).build() {
};
__name(_CreateRepositoryCommand, "CreateRepositoryCommand");
var CreateRepositoryCommand = _CreateRepositoryCommand;

// src/commands/CreateRepositoryCreationTemplateCommand.ts



var _CreateRepositoryCreationTemplateCommand = class _CreateRepositoryCreationTemplateCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "CreateRepositoryCreationTemplate", {}).n("ECRClient", "CreateRepositoryCreationTemplateCommand").f(void 0, void 0).ser(se_CreateRepositoryCreationTemplateCommand).de(de_CreateRepositoryCreationTemplateCommand).build() {
};
__name(_CreateRepositoryCreationTemplateCommand, "CreateRepositoryCreationTemplateCommand");
var CreateRepositoryCreationTemplateCommand = _CreateRepositoryCreationTemplateCommand;

// src/commands/DeleteLifecyclePolicyCommand.ts



var _DeleteLifecyclePolicyCommand = class _DeleteLifecyclePolicyCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "DeleteLifecyclePolicy", {}).n("ECRClient", "DeleteLifecyclePolicyCommand").f(void 0, void 0).ser(se_DeleteLifecyclePolicyCommand).de(de_DeleteLifecyclePolicyCommand).build() {
};
__name(_DeleteLifecyclePolicyCommand, "DeleteLifecyclePolicyCommand");
var DeleteLifecyclePolicyCommand = _DeleteLifecyclePolicyCommand;

// src/commands/DeletePullThroughCacheRuleCommand.ts



var _DeletePullThroughCacheRuleCommand = class _DeletePullThroughCacheRuleCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "DeletePullThroughCacheRule", {}).n("ECRClient", "DeletePullThroughCacheRuleCommand").f(void 0, void 0).ser(se_DeletePullThroughCacheRuleCommand).de(de_DeletePullThroughCacheRuleCommand).build() {
};
__name(_DeletePullThroughCacheRuleCommand, "DeletePullThroughCacheRuleCommand");
var DeletePullThroughCacheRuleCommand = _DeletePullThroughCacheRuleCommand;

// src/commands/DeleteRegistryPolicyCommand.ts



var _DeleteRegistryPolicyCommand = class _DeleteRegistryPolicyCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "DeleteRegistryPolicy", {}).n("ECRClient", "DeleteRegistryPolicyCommand").f(void 0, void 0).ser(se_DeleteRegistryPolicyCommand).de(de_DeleteRegistryPolicyCommand).build() {
};
__name(_DeleteRegistryPolicyCommand, "DeleteRegistryPolicyCommand");
var DeleteRegistryPolicyCommand = _DeleteRegistryPolicyCommand;

// src/commands/DeleteRepositoryCommand.ts



var _DeleteRepositoryCommand = class _DeleteRepositoryCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "DeleteRepository", {}).n("ECRClient", "DeleteRepositoryCommand").f(void 0, void 0).ser(se_DeleteRepositoryCommand).de(de_DeleteRepositoryCommand).build() {
};
__name(_DeleteRepositoryCommand, "DeleteRepositoryCommand");
var DeleteRepositoryCommand = _DeleteRepositoryCommand;

// src/commands/DeleteRepositoryCreationTemplateCommand.ts



var _DeleteRepositoryCreationTemplateCommand = class _DeleteRepositoryCreationTemplateCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "DeleteRepositoryCreationTemplate", {}).n("ECRClient", "DeleteRepositoryCreationTemplateCommand").f(void 0, void 0).ser(se_DeleteRepositoryCreationTemplateCommand).de(de_DeleteRepositoryCreationTemplateCommand).build() {
};
__name(_DeleteRepositoryCreationTemplateCommand, "DeleteRepositoryCreationTemplateCommand");
var DeleteRepositoryCreationTemplateCommand = _DeleteRepositoryCreationTemplateCommand;

// src/commands/DeleteRepositoryPolicyCommand.ts



var _DeleteRepositoryPolicyCommand = class _DeleteRepositoryPolicyCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "DeleteRepositoryPolicy", {}).n("ECRClient", "DeleteRepositoryPolicyCommand").f(void 0, void 0).ser(se_DeleteRepositoryPolicyCommand).de(de_DeleteRepositoryPolicyCommand).build() {
};
__name(_DeleteRepositoryPolicyCommand, "DeleteRepositoryPolicyCommand");
var DeleteRepositoryPolicyCommand = _DeleteRepositoryPolicyCommand;

// src/commands/DescribeImageReplicationStatusCommand.ts



var _DescribeImageReplicationStatusCommand = class _DescribeImageReplicationStatusCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "DescribeImageReplicationStatus", {}).n("ECRClient", "DescribeImageReplicationStatusCommand").f(void 0, void 0).ser(se_DescribeImageReplicationStatusCommand).de(de_DescribeImageReplicationStatusCommand).build() {
};
__name(_DescribeImageReplicationStatusCommand, "DescribeImageReplicationStatusCommand");
var DescribeImageReplicationStatusCommand = _DescribeImageReplicationStatusCommand;

// src/commands/DescribeImageScanFindingsCommand.ts



var _DescribeImageScanFindingsCommand = class _DescribeImageScanFindingsCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "DescribeImageScanFindings", {}).n("ECRClient", "DescribeImageScanFindingsCommand").f(void 0, void 0).ser(se_DescribeImageScanFindingsCommand).de(de_DescribeImageScanFindingsCommand).build() {
};
__name(_DescribeImageScanFindingsCommand, "DescribeImageScanFindingsCommand");
var DescribeImageScanFindingsCommand = _DescribeImageScanFindingsCommand;

// src/commands/DescribeImagesCommand.ts



var _DescribeImagesCommand = class _DescribeImagesCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "DescribeImages", {}).n("ECRClient", "DescribeImagesCommand").f(void 0, void 0).ser(se_DescribeImagesCommand).de(de_DescribeImagesCommand).build() {
};
__name(_DescribeImagesCommand, "DescribeImagesCommand");
var DescribeImagesCommand = _DescribeImagesCommand;

// src/commands/DescribePullThroughCacheRulesCommand.ts



var _DescribePullThroughCacheRulesCommand = class _DescribePullThroughCacheRulesCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "DescribePullThroughCacheRules", {}).n("ECRClient", "DescribePullThroughCacheRulesCommand").f(void 0, void 0).ser(se_DescribePullThroughCacheRulesCommand).de(de_DescribePullThroughCacheRulesCommand).build() {
};
__name(_DescribePullThroughCacheRulesCommand, "DescribePullThroughCacheRulesCommand");
var DescribePullThroughCacheRulesCommand = _DescribePullThroughCacheRulesCommand;

// src/commands/DescribeRegistryCommand.ts



var _DescribeRegistryCommand = class _DescribeRegistryCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "DescribeRegistry", {}).n("ECRClient", "DescribeRegistryCommand").f(void 0, void 0).ser(se_DescribeRegistryCommand).de(de_DescribeRegistryCommand).build() {
};
__name(_DescribeRegistryCommand, "DescribeRegistryCommand");
var DescribeRegistryCommand = _DescribeRegistryCommand;

// src/commands/DescribeRepositoriesCommand.ts



var _DescribeRepositoriesCommand = class _DescribeRepositoriesCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "DescribeRepositories", {}).n("ECRClient", "DescribeRepositoriesCommand").f(void 0, void 0).ser(se_DescribeRepositoriesCommand).de(de_DescribeRepositoriesCommand).build() {
};
__name(_DescribeRepositoriesCommand, "DescribeRepositoriesCommand");
var DescribeRepositoriesCommand = _DescribeRepositoriesCommand;

// src/commands/DescribeRepositoryCreationTemplatesCommand.ts



var _DescribeRepositoryCreationTemplatesCommand = class _DescribeRepositoryCreationTemplatesCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "DescribeRepositoryCreationTemplates", {}).n("ECRClient", "DescribeRepositoryCreationTemplatesCommand").f(void 0, void 0).ser(se_DescribeRepositoryCreationTemplatesCommand).de(de_DescribeRepositoryCreationTemplatesCommand).build() {
};
__name(_DescribeRepositoryCreationTemplatesCommand, "DescribeRepositoryCreationTemplatesCommand");
var DescribeRepositoryCreationTemplatesCommand = _DescribeRepositoryCreationTemplatesCommand;

// src/commands/GetAuthorizationTokenCommand.ts



var _GetAuthorizationTokenCommand = class _GetAuthorizationTokenCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "GetAuthorizationToken", {}).n("ECRClient", "GetAuthorizationTokenCommand").f(void 0, void 0).ser(se_GetAuthorizationTokenCommand).de(de_GetAuthorizationTokenCommand).build() {
};
__name(_GetAuthorizationTokenCommand, "GetAuthorizationTokenCommand");
var GetAuthorizationTokenCommand = _GetAuthorizationTokenCommand;

// src/commands/GetDownloadUrlForLayerCommand.ts



var _GetDownloadUrlForLayerCommand = class _GetDownloadUrlForLayerCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "GetDownloadUrlForLayer", {}).n("ECRClient", "GetDownloadUrlForLayerCommand").f(void 0, void 0).ser(se_GetDownloadUrlForLayerCommand).de(de_GetDownloadUrlForLayerCommand).build() {
};
__name(_GetDownloadUrlForLayerCommand, "GetDownloadUrlForLayerCommand");
var GetDownloadUrlForLayerCommand = _GetDownloadUrlForLayerCommand;

// src/commands/GetLifecyclePolicyCommand.ts



var _GetLifecyclePolicyCommand = class _GetLifecyclePolicyCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "GetLifecyclePolicy", {}).n("ECRClient", "GetLifecyclePolicyCommand").f(void 0, void 0).ser(se_GetLifecyclePolicyCommand).de(de_GetLifecyclePolicyCommand).build() {
};
__name(_GetLifecyclePolicyCommand, "GetLifecyclePolicyCommand");
var GetLifecyclePolicyCommand = _GetLifecyclePolicyCommand;

// src/commands/GetLifecyclePolicyPreviewCommand.ts



var _GetLifecyclePolicyPreviewCommand = class _GetLifecyclePolicyPreviewCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "GetLifecyclePolicyPreview", {}).n("ECRClient", "GetLifecyclePolicyPreviewCommand").f(void 0, void 0).ser(se_GetLifecyclePolicyPreviewCommand).de(de_GetLifecyclePolicyPreviewCommand).build() {
};
__name(_GetLifecyclePolicyPreviewCommand, "GetLifecyclePolicyPreviewCommand");
var GetLifecyclePolicyPreviewCommand = _GetLifecyclePolicyPreviewCommand;

// src/commands/GetRegistryPolicyCommand.ts



var _GetRegistryPolicyCommand = class _GetRegistryPolicyCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "GetRegistryPolicy", {}).n("ECRClient", "GetRegistryPolicyCommand").f(void 0, void 0).ser(se_GetRegistryPolicyCommand).de(de_GetRegistryPolicyCommand).build() {
};
__name(_GetRegistryPolicyCommand, "GetRegistryPolicyCommand");
var GetRegistryPolicyCommand = _GetRegistryPolicyCommand;

// src/commands/GetRegistryScanningConfigurationCommand.ts



var _GetRegistryScanningConfigurationCommand = class _GetRegistryScanningConfigurationCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "GetRegistryScanningConfiguration", {}).n("ECRClient", "GetRegistryScanningConfigurationCommand").f(void 0, void 0).ser(se_GetRegistryScanningConfigurationCommand).de(de_GetRegistryScanningConfigurationCommand).build() {
};
__name(_GetRegistryScanningConfigurationCommand, "GetRegistryScanningConfigurationCommand");
var GetRegistryScanningConfigurationCommand = _GetRegistryScanningConfigurationCommand;

// src/commands/GetRepositoryPolicyCommand.ts



var _GetRepositoryPolicyCommand = class _GetRepositoryPolicyCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "GetRepositoryPolicy", {}).n("ECRClient", "GetRepositoryPolicyCommand").f(void 0, void 0).ser(se_GetRepositoryPolicyCommand).de(de_GetRepositoryPolicyCommand).build() {
};
__name(_GetRepositoryPolicyCommand, "GetRepositoryPolicyCommand");
var GetRepositoryPolicyCommand = _GetRepositoryPolicyCommand;

// src/commands/InitiateLayerUploadCommand.ts



var _InitiateLayerUploadCommand = class _InitiateLayerUploadCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "InitiateLayerUpload", {}).n("ECRClient", "InitiateLayerUploadCommand").f(void 0, void 0).ser(se_InitiateLayerUploadCommand).de(de_InitiateLayerUploadCommand).build() {
};
__name(_InitiateLayerUploadCommand, "InitiateLayerUploadCommand");
var InitiateLayerUploadCommand = _InitiateLayerUploadCommand;

// src/commands/ListImagesCommand.ts



var _ListImagesCommand = class _ListImagesCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "ListImages", {}).n("ECRClient", "ListImagesCommand").f(void 0, void 0).ser(se_ListImagesCommand).de(de_ListImagesCommand).build() {
};
__name(_ListImagesCommand, "ListImagesCommand");
var ListImagesCommand = _ListImagesCommand;

// src/commands/ListTagsForResourceCommand.ts



var _ListTagsForResourceCommand = class _ListTagsForResourceCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "ListTagsForResource", {}).n("ECRClient", "ListTagsForResourceCommand").f(void 0, void 0).ser(se_ListTagsForResourceCommand).de(de_ListTagsForResourceCommand).build() {
};
__name(_ListTagsForResourceCommand, "ListTagsForResourceCommand");
var ListTagsForResourceCommand = _ListTagsForResourceCommand;

// src/commands/PutImageCommand.ts



var _PutImageCommand = class _PutImageCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "PutImage", {}).n("ECRClient", "PutImageCommand").f(void 0, void 0).ser(se_PutImageCommand).de(de_PutImageCommand).build() {
};
__name(_PutImageCommand, "PutImageCommand");
var PutImageCommand = _PutImageCommand;

// src/commands/PutImageScanningConfigurationCommand.ts



var _PutImageScanningConfigurationCommand = class _PutImageScanningConfigurationCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "PutImageScanningConfiguration", {}).n("ECRClient", "PutImageScanningConfigurationCommand").f(void 0, void 0).ser(se_PutImageScanningConfigurationCommand).de(de_PutImageScanningConfigurationCommand).build() {
};
__name(_PutImageScanningConfigurationCommand, "PutImageScanningConfigurationCommand");
var PutImageScanningConfigurationCommand = _PutImageScanningConfigurationCommand;

// src/commands/PutImageTagMutabilityCommand.ts



var _PutImageTagMutabilityCommand = class _PutImageTagMutabilityCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "PutImageTagMutability", {}).n("ECRClient", "PutImageTagMutabilityCommand").f(void 0, void 0).ser(se_PutImageTagMutabilityCommand).de(de_PutImageTagMutabilityCommand).build() {
};
__name(_PutImageTagMutabilityCommand, "PutImageTagMutabilityCommand");
var PutImageTagMutabilityCommand = _PutImageTagMutabilityCommand;

// src/commands/PutLifecyclePolicyCommand.ts



var _PutLifecyclePolicyCommand = class _PutLifecyclePolicyCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "PutLifecyclePolicy", {}).n("ECRClient", "PutLifecyclePolicyCommand").f(void 0, void 0).ser(se_PutLifecyclePolicyCommand).de(de_PutLifecyclePolicyCommand).build() {
};
__name(_PutLifecyclePolicyCommand, "PutLifecyclePolicyCommand");
var PutLifecyclePolicyCommand = _PutLifecyclePolicyCommand;

// src/commands/PutRegistryPolicyCommand.ts



var _PutRegistryPolicyCommand = class _PutRegistryPolicyCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "PutRegistryPolicy", {}).n("ECRClient", "PutRegistryPolicyCommand").f(void 0, void 0).ser(se_PutRegistryPolicyCommand).de(de_PutRegistryPolicyCommand).build() {
};
__name(_PutRegistryPolicyCommand, "PutRegistryPolicyCommand");
var PutRegistryPolicyCommand = _PutRegistryPolicyCommand;

// src/commands/PutRegistryScanningConfigurationCommand.ts



var _PutRegistryScanningConfigurationCommand = class _PutRegistryScanningConfigurationCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "PutRegistryScanningConfiguration", {}).n("ECRClient", "PutRegistryScanningConfigurationCommand").f(void 0, void 0).ser(se_PutRegistryScanningConfigurationCommand).de(de_PutRegistryScanningConfigurationCommand).build() {
};
__name(_PutRegistryScanningConfigurationCommand, "PutRegistryScanningConfigurationCommand");
var PutRegistryScanningConfigurationCommand = _PutRegistryScanningConfigurationCommand;

// src/commands/PutReplicationConfigurationCommand.ts



var _PutReplicationConfigurationCommand = class _PutReplicationConfigurationCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "PutReplicationConfiguration", {}).n("ECRClient", "PutReplicationConfigurationCommand").f(void 0, void 0).ser(se_PutReplicationConfigurationCommand).de(de_PutReplicationConfigurationCommand).build() {
};
__name(_PutReplicationConfigurationCommand, "PutReplicationConfigurationCommand");
var PutReplicationConfigurationCommand = _PutReplicationConfigurationCommand;

// src/commands/SetRepositoryPolicyCommand.ts



var _SetRepositoryPolicyCommand = class _SetRepositoryPolicyCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "SetRepositoryPolicy", {}).n("ECRClient", "SetRepositoryPolicyCommand").f(void 0, void 0).ser(se_SetRepositoryPolicyCommand).de(de_SetRepositoryPolicyCommand).build() {
};
__name(_SetRepositoryPolicyCommand, "SetRepositoryPolicyCommand");
var SetRepositoryPolicyCommand = _SetRepositoryPolicyCommand;

// src/commands/StartImageScanCommand.ts



var _StartImageScanCommand = class _StartImageScanCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "StartImageScan", {}).n("ECRClient", "StartImageScanCommand").f(void 0, void 0).ser(se_StartImageScanCommand).de(de_StartImageScanCommand).build() {
};
__name(_StartImageScanCommand, "StartImageScanCommand");
var StartImageScanCommand = _StartImageScanCommand;

// src/commands/StartLifecyclePolicyPreviewCommand.ts



var _StartLifecyclePolicyPreviewCommand = class _StartLifecyclePolicyPreviewCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "StartLifecyclePolicyPreview", {}).n("ECRClient", "StartLifecyclePolicyPreviewCommand").f(void 0, void 0).ser(se_StartLifecyclePolicyPreviewCommand).de(de_StartLifecyclePolicyPreviewCommand).build() {
};
__name(_StartLifecyclePolicyPreviewCommand, "StartLifecyclePolicyPreviewCommand");
var StartLifecyclePolicyPreviewCommand = _StartLifecyclePolicyPreviewCommand;

// src/commands/TagResourceCommand.ts



var _TagResourceCommand = class _TagResourceCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "TagResource", {}).n("ECRClient", "TagResourceCommand").f(void 0, void 0).ser(se_TagResourceCommand).de(de_TagResourceCommand).build() {
};
__name(_TagResourceCommand, "TagResourceCommand");
var TagResourceCommand = _TagResourceCommand;

// src/commands/UntagResourceCommand.ts



var _UntagResourceCommand = class _UntagResourceCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "UntagResource", {}).n("ECRClient", "UntagResourceCommand").f(void 0, void 0).ser(se_UntagResourceCommand).de(de_UntagResourceCommand).build() {
};
__name(_UntagResourceCommand, "UntagResourceCommand");
var UntagResourceCommand = _UntagResourceCommand;

// src/commands/UpdatePullThroughCacheRuleCommand.ts



var _UpdatePullThroughCacheRuleCommand = class _UpdatePullThroughCacheRuleCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "UpdatePullThroughCacheRule", {}).n("ECRClient", "UpdatePullThroughCacheRuleCommand").f(void 0, void 0).ser(se_UpdatePullThroughCacheRuleCommand).de(de_UpdatePullThroughCacheRuleCommand).build() {
};
__name(_UpdatePullThroughCacheRuleCommand, "UpdatePullThroughCacheRuleCommand");
var UpdatePullThroughCacheRuleCommand = _UpdatePullThroughCacheRuleCommand;

// src/commands/UpdateRepositoryCreationTemplateCommand.ts



var _UpdateRepositoryCreationTemplateCommand = class _UpdateRepositoryCreationTemplateCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "UpdateRepositoryCreationTemplate", {}).n("ECRClient", "UpdateRepositoryCreationTemplateCommand").f(void 0, void 0).ser(se_UpdateRepositoryCreationTemplateCommand).de(de_UpdateRepositoryCreationTemplateCommand).build() {
};
__name(_UpdateRepositoryCreationTemplateCommand, "UpdateRepositoryCreationTemplateCommand");
var UpdateRepositoryCreationTemplateCommand = _UpdateRepositoryCreationTemplateCommand;

// src/commands/UploadLayerPartCommand.ts



var _UploadLayerPartCommand = class _UploadLayerPartCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "UploadLayerPart", {}).n("ECRClient", "UploadLayerPartCommand").f(void 0, void 0).ser(se_UploadLayerPartCommand).de(de_UploadLayerPartCommand).build() {
};
__name(_UploadLayerPartCommand, "UploadLayerPartCommand");
var UploadLayerPartCommand = _UploadLayerPartCommand;

// src/commands/ValidatePullThroughCacheRuleCommand.ts



var _ValidatePullThroughCacheRuleCommand = class _ValidatePullThroughCacheRuleCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AmazonEC2ContainerRegistry_V20150921", "ValidatePullThroughCacheRule", {}).n("ECRClient", "ValidatePullThroughCacheRuleCommand").f(void 0, void 0).ser(se_ValidatePullThroughCacheRuleCommand).de(de_ValidatePullThroughCacheRuleCommand).build() {
};
__name(_ValidatePullThroughCacheRuleCommand, "ValidatePullThroughCacheRuleCommand");
var ValidatePullThroughCacheRuleCommand = _ValidatePullThroughCacheRuleCommand;

// src/ECR.ts
var commands = {
  BatchCheckLayerAvailabilityCommand,
  BatchDeleteImageCommand,
  BatchGetImageCommand,
  BatchGetRepositoryScanningConfigurationCommand,
  CompleteLayerUploadCommand,
  CreatePullThroughCacheRuleCommand,
  CreateRepositoryCommand,
  CreateRepositoryCreationTemplateCommand,
  DeleteLifecyclePolicyCommand,
  DeletePullThroughCacheRuleCommand,
  DeleteRegistryPolicyCommand,
  DeleteRepositoryCommand,
  DeleteRepositoryCreationTemplateCommand,
  DeleteRepositoryPolicyCommand,
  DescribeImageReplicationStatusCommand,
  DescribeImagesCommand,
  DescribeImageScanFindingsCommand,
  DescribePullThroughCacheRulesCommand,
  DescribeRegistryCommand,
  DescribeRepositoriesCommand,
  DescribeRepositoryCreationTemplatesCommand,
  GetAuthorizationTokenCommand,
  GetDownloadUrlForLayerCommand,
  GetLifecyclePolicyCommand,
  GetLifecyclePolicyPreviewCommand,
  GetRegistryPolicyCommand,
  GetRegistryScanningConfigurationCommand,
  GetRepositoryPolicyCommand,
  InitiateLayerUploadCommand,
  ListImagesCommand,
  ListTagsForResourceCommand,
  PutImageCommand,
  PutImageScanningConfigurationCommand,
  PutImageTagMutabilityCommand,
  PutLifecyclePolicyCommand,
  PutRegistryPolicyCommand,
  PutRegistryScanningConfigurationCommand,
  PutReplicationConfigurationCommand,
  SetRepositoryPolicyCommand,
  StartImageScanCommand,
  StartLifecyclePolicyPreviewCommand,
  TagResourceCommand,
  UntagResourceCommand,
  UpdatePullThroughCacheRuleCommand,
  UpdateRepositoryCreationTemplateCommand,
  UploadLayerPartCommand,
  ValidatePullThroughCacheRuleCommand
};
var _ECR = class _ECR extends ECRClient {
};
__name(_ECR, "ECR");
var ECR = _ECR;
(0, import_smithy_client.createAggregatedClient)(commands, ECR);

// src/pagination/DescribeImageScanFindingsPaginator.ts

var paginateDescribeImageScanFindings = (0, import_core.createPaginator)(ECRClient, DescribeImageScanFindingsCommand, "nextToken", "nextToken", "maxResults");

// src/pagination/DescribeImagesPaginator.ts

var paginateDescribeImages = (0, import_core.createPaginator)(ECRClient, DescribeImagesCommand, "nextToken", "nextToken", "maxResults");

// src/pagination/DescribePullThroughCacheRulesPaginator.ts

var paginateDescribePullThroughCacheRules = (0, import_core.createPaginator)(ECRClient, DescribePullThroughCacheRulesCommand, "nextToken", "nextToken", "maxResults");

// src/pagination/DescribeRepositoriesPaginator.ts

var paginateDescribeRepositories = (0, import_core.createPaginator)(ECRClient, DescribeRepositoriesCommand, "nextToken", "nextToken", "maxResults");

// src/pagination/DescribeRepositoryCreationTemplatesPaginator.ts

var paginateDescribeRepositoryCreationTemplates = (0, import_core.createPaginator)(ECRClient, DescribeRepositoryCreationTemplatesCommand, "nextToken", "nextToken", "maxResults");

// src/pagination/GetLifecyclePolicyPreviewPaginator.ts

var paginateGetLifecyclePolicyPreview = (0, import_core.createPaginator)(ECRClient, GetLifecyclePolicyPreviewCommand, "nextToken", "nextToken", "maxResults");

// src/pagination/ListImagesPaginator.ts

var paginateListImages = (0, import_core.createPaginator)(ECRClient, ListImagesCommand, "nextToken", "nextToken", "maxResults");

// src/waiters/waitForImageScanComplete.ts
var import_util_waiter = __nccwpck_require__(8011);
var checkState = /* @__PURE__ */ __name(async (client, input) => {
  let reason;
  try {
    const result = await client.send(new DescribeImageScanFindingsCommand(input));
    reason = result;
    try {
      const returnComparator = /* @__PURE__ */ __name(() => {
        return result.imageScanStatus.status;
      }, "returnComparator");
      if (returnComparator() === "COMPLETE") {
        return { state: import_util_waiter.WaiterState.SUCCESS, reason };
      }
    } catch (e) {
    }
    try {
      const returnComparator = /* @__PURE__ */ __name(() => {
        return result.imageScanStatus.status;
      }, "returnComparator");
      if (returnComparator() === "FAILED") {
        return { state: import_util_waiter.WaiterState.FAILURE, reason };
      }
    } catch (e) {
    }
  } catch (exception) {
    reason = exception;
  }
  return { state: import_util_waiter.WaiterState.RETRY, reason };
}, "checkState");
var waitForImageScanComplete = /* @__PURE__ */ __name(async (params, input) => {
  const serviceDefaults = { minDelay: 5, maxDelay: 120 };
  return (0, import_util_waiter.createWaiter)({ ...serviceDefaults, ...params }, input, checkState);
}, "waitForImageScanComplete");
var waitUntilImageScanComplete = /* @__PURE__ */ __name(async (params, input) => {
  const serviceDefaults = { minDelay: 5, maxDelay: 120 };
  const result = await (0, import_util_waiter.createWaiter)({ ...serviceDefaults, ...params }, input, checkState);
  return (0, import_util_waiter.checkExceptions)(result);
}, "waitUntilImageScanComplete");

// src/waiters/waitForLifecyclePolicyPreviewComplete.ts

var checkState2 = /* @__PURE__ */ __name(async (client, input) => {
  let reason;
  try {
    const result = await client.send(new GetLifecyclePolicyPreviewCommand(input));
    reason = result;
    try {
      const returnComparator = /* @__PURE__ */ __name(() => {
        return result.status;
      }, "returnComparator");
      if (returnComparator() === "COMPLETE") {
        return { state: import_util_waiter.WaiterState.SUCCESS, reason };
      }
    } catch (e) {
    }
    try {
      const returnComparator = /* @__PURE__ */ __name(() => {
        return result.status;
      }, "returnComparator");
      if (returnComparator() === "FAILED") {
        return { state: import_util_waiter.WaiterState.FAILURE, reason };
      }
    } catch (e) {
    }
  } catch (exception) {
    reason = exception;
  }
  return { state: import_util_waiter.WaiterState.RETRY, reason };
}, "checkState");
var waitForLifecyclePolicyPreviewComplete = /* @__PURE__ */ __name(async (params, input) => {
  const serviceDefaults = { minDelay: 5, maxDelay: 120 };
  return (0, import_util_waiter.createWaiter)({ ...serviceDefaults, ...params }, input, checkState2);
}, "waitForLifecyclePolicyPreviewComplete");
var waitUntilLifecyclePolicyPreviewComplete = /* @__PURE__ */ __name(async (params, input) => {
  const serviceDefaults = { minDelay: 5, maxDelay: 120 };
  const result = await (0, import_util_waiter.createWaiter)({ ...serviceDefaults, ...params }, input, checkState2);
  return (0, import_util_waiter.checkExceptions)(result);
}, "waitUntilLifecyclePolicyPreviewComplete");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 869:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.getRuntimeConfig = void 0;
const tslib_1 = __nccwpck_require__(4351);
const package_json_1 = tslib_1.__importDefault(__nccwpck_require__(4289));
const core_1 = __nccwpck_require__(9963);
const credential_provider_node_1 = __nccwpck_require__(5531);
const util_user_agent_node_1 = __nccwpck_require__(8095);
const config_resolver_1 = __nccwpck_require__(3098);
const hash_node_1 = __nccwpck_require__(3081);
const middleware_retry_1 = __nccwpck_require__(6039);
const node_config_provider_1 = __nccwpck_require__(3461);
const node_http_handler_1 = __nccwpck_require__(258);
const util_body_length_node_1 = __nccwpck_require__(8075);
const util_retry_1 = __nccwpck_require__(4902);
const runtimeConfig_shared_1 = __nccwpck_require__(542);
const smithy_client_1 = __nccwpck_require__(3570);
const util_defaults_mode_node_1 = __nccwpck_require__(2429);
const smithy_client_2 = __nccwpck_require__(3570);
const getRuntimeConfig = (config) => {
    (0, smithy_client_2.emitWarningIfUnsupportedVersion)(process.version);
    const defaultsMode = (0, util_defaults_mode_node_1.resolveDefaultsModeConfig)(config);
    const defaultConfigProvider = () => defaultsMode().then(smithy_client_1.loadConfigsForDefaultMode);
    const clientSharedValues = (0, runtimeConfig_shared_1.getRuntimeConfig)(config);
    (0, core_1.emitWarningIfUnsupportedVersion)(process.version);
    return {
        ...clientSharedValues,
        ...config,
        runtime: "node",
        defaultsMode,
        bodyLengthChecker: config?.bodyLengthChecker ?? util_body_length_node_1.calculateBodyLength,
        credentialDefaultProvider: config?.credentialDefaultProvider ?? credential_provider_node_1.defaultProvider,
        defaultUserAgentProvider: config?.defaultUserAgentProvider ??
            (0, util_user_agent_node_1.defaultUserAgent)({ serviceId: clientSharedValues.serviceId, clientVersion: package_json_1.default.version }),
        maxAttempts: config?.maxAttempts ?? (0, node_config_provider_1.loadConfig)(middleware_retry_1.NODE_MAX_ATTEMPT_CONFIG_OPTIONS),
        region: config?.region ?? (0, node_config_provider_1.loadConfig)(config_resolver_1.NODE_REGION_CONFIG_OPTIONS, config_resolver_1.NODE_REGION_CONFIG_FILE_OPTIONS),
        requestHandler: node_http_handler_1.NodeHttpHandler.create(config?.requestHandler ?? defaultConfigProvider),
        retryMode: config?.retryMode ??
            (0, node_config_provider_1.loadConfig)({
                ...middleware_retry_1.NODE_RETRY_MODE_CONFIG_OPTIONS,
                default: async () => (await defaultConfigProvider()).retryMode || util_retry_1.DEFAULT_RETRY_MODE,
            }),
        sha256: config?.sha256 ?? hash_node_1.Hash.bind(null, "sha256"),
        streamCollector: config?.streamCollector ?? node_http_handler_1.streamCollector,
        useDualstackEndpoint: config?.useDualstackEndpoint ?? (0, node_config_provider_1.loadConfig)(config_resolver_1.NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS),
        useFipsEndpoint: config?.useFipsEndpoint ?? (0, node_config_provider_1.loadConfig)(config_resolver_1.NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS),
    };
};
exports.getRuntimeConfig = getRuntimeConfig;


/***/ }),

/***/ 542:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.getRuntimeConfig = void 0;
const core_1 = __nccwpck_require__(9963);
const smithy_client_1 = __nccwpck_require__(3570);
const url_parser_1 = __nccwpck_require__(4681);
const util_base64_1 = __nccwpck_require__(5600);
const util_utf8_1 = __nccwpck_require__(1895);
const httpAuthSchemeProvider_1 = __nccwpck_require__(4682);
const endpointResolver_1 = __nccwpck_require__(1610);
const getRuntimeConfig = (config) => {
    return {
        apiVersion: "2015-09-21",
        base64Decoder: config?.base64Decoder ?? util_base64_1.fromBase64,
        base64Encoder: config?.base64Encoder ?? util_base64_1.toBase64,
        disableHostPrefix: config?.disableHostPrefix ?? false,
        endpointProvider: config?.endpointProvider ?? endpointResolver_1.defaultEndpointResolver,
        extensions: config?.extensions ?? [],
        httpAuthSchemeProvider: config?.httpAuthSchemeProvider ?? httpAuthSchemeProvider_1.defaultECRHttpAuthSchemeProvider,
        httpAuthSchemes: config?.httpAuthSchemes ?? [
            {
                schemeId: "aws.auth#sigv4",
                identityProvider: (ipc) => ipc.getIdentityProvider("aws.auth#sigv4"),
                signer: new core_1.AwsSdkSigV4Signer(),
            },
        ],
        logger: config?.logger ?? new smithy_client_1.NoOpLogger(),
        serviceId: config?.serviceId ?? "ECR",
        urlParser: config?.urlParser ?? url_parser_1.parseUrl,
        utf8Decoder: config?.utf8Decoder ?? util_utf8_1.fromUtf8,
        utf8Encoder: config?.utf8Encoder ?? util_utf8_1.toUtf8,
    };
};
exports.getRuntimeConfig = getRuntimeConfig;


/***/ }),

/***/ 6948:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.resolveHttpAuthSchemeConfig = exports.defaultSSOOIDCHttpAuthSchemeProvider = exports.defaultSSOOIDCHttpAuthSchemeParametersProvider = void 0;
const core_1 = __nccwpck_require__(9963);
const util_middleware_1 = __nccwpck_require__(2390);
const defaultSSOOIDCHttpAuthSchemeParametersProvider = async (config, context, input) => {
    return {
        operation: (0, util_middleware_1.getSmithyContext)(context).operation,
        region: (await (0, util_middleware_1.normalizeProvider)(config.region)()) ||
            (() => {
                throw new Error("expected `region` to be configured for `aws.auth#sigv4`");
            })(),
    };
};
exports.defaultSSOOIDCHttpAuthSchemeParametersProvider = defaultSSOOIDCHttpAuthSchemeParametersProvider;
function createAwsAuthSigv4HttpAuthOption(authParameters) {
    return {
        schemeId: "aws.auth#sigv4",
        signingProperties: {
            name: "sso-oauth",
            region: authParameters.region,
        },
        propertiesExtractor: (config, context) => ({
            signingProperties: {
                config,
                context,
            },
        }),
    };
}
function createSmithyApiNoAuthHttpAuthOption(authParameters) {
    return {
        schemeId: "smithy.api#noAuth",
    };
}
const defaultSSOOIDCHttpAuthSchemeProvider = (authParameters) => {
    const options = [];
    switch (authParameters.operation) {
        case "CreateToken": {
            options.push(createSmithyApiNoAuthHttpAuthOption(authParameters));
            break;
        }
        case "RegisterClient": {
            options.push(createSmithyApiNoAuthHttpAuthOption(authParameters));
            break;
        }
        case "StartDeviceAuthorization": {
            options.push(createSmithyApiNoAuthHttpAuthOption(authParameters));
            break;
        }
        default: {
            options.push(createAwsAuthSigv4HttpAuthOption(authParameters));
        }
    }
    return options;
};
exports.defaultSSOOIDCHttpAuthSchemeProvider = defaultSSOOIDCHttpAuthSchemeProvider;
const resolveHttpAuthSchemeConfig = (config) => {
    const config_0 = (0, core_1.resolveAwsSdkSigV4Config)(config);
    return {
        ...config_0,
    };
};
exports.resolveHttpAuthSchemeConfig = resolveHttpAuthSchemeConfig;


/***/ }),

/***/ 7604:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.defaultEndpointResolver = void 0;
const util_endpoints_1 = __nccwpck_require__(3350);
const util_endpoints_2 = __nccwpck_require__(5473);
const ruleset_1 = __nccwpck_require__(1756);
const defaultEndpointResolver = (endpointParams, context = {}) => {
    return (0, util_endpoints_2.resolveEndpoint)(ruleset_1.ruleSet, {
        endpointParams: endpointParams,
        logger: context.logger,
    });
};
exports.defaultEndpointResolver = defaultEndpointResolver;
util_endpoints_2.customEndpointFunctions.aws = util_endpoints_1.awsEndpointFunctions;


/***/ }),

/***/ 1756:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ruleSet = void 0;
const u = "required", v = "fn", w = "argv", x = "ref";
const a = true, b = "isSet", c = "booleanEquals", d = "error", e = "endpoint", f = "tree", g = "PartitionResult", h = "getAttr", i = { [u]: false, "type": "String" }, j = { [u]: true, "default": false, "type": "Boolean" }, k = { [x]: "Endpoint" }, l = { [v]: c, [w]: [{ [x]: "UseFIPS" }, true] }, m = { [v]: c, [w]: [{ [x]: "UseDualStack" }, true] }, n = {}, o = { [v]: h, [w]: [{ [x]: g }, "supportsFIPS"] }, p = { [x]: g }, q = { [v]: c, [w]: [true, { [v]: h, [w]: [p, "supportsDualStack"] }] }, r = [l], s = [m], t = [{ [x]: "Region" }];
const _data = { version: "1.0", parameters: { Region: i, UseDualStack: j, UseFIPS: j, Endpoint: i }, rules: [{ conditions: [{ [v]: b, [w]: [k] }], rules: [{ conditions: r, error: "Invalid Configuration: FIPS and custom endpoint are not supported", type: d }, { conditions: s, error: "Invalid Configuration: Dualstack and custom endpoint are not supported", type: d }, { endpoint: { url: k, properties: n, headers: n }, type: e }], type: f }, { conditions: [{ [v]: b, [w]: t }], rules: [{ conditions: [{ [v]: "aws.partition", [w]: t, assign: g }], rules: [{ conditions: [l, m], rules: [{ conditions: [{ [v]: c, [w]: [a, o] }, q], rules: [{ endpoint: { url: "https://oidc-fips.{Region}.{PartitionResult#dualStackDnsSuffix}", properties: n, headers: n }, type: e }], type: f }, { error: "FIPS and DualStack are enabled, but this partition does not support one or both", type: d }], type: f }, { conditions: r, rules: [{ conditions: [{ [v]: c, [w]: [o, a] }], rules: [{ conditions: [{ [v]: "stringEquals", [w]: [{ [v]: h, [w]: [p, "name"] }, "aws-us-gov"] }], endpoint: { url: "https://oidc.{Region}.amazonaws.com", properties: n, headers: n }, type: e }, { endpoint: { url: "https://oidc-fips.{Region}.{PartitionResult#dnsSuffix}", properties: n, headers: n }, type: e }], type: f }, { error: "FIPS is enabled but this partition does not support FIPS", type: d }], type: f }, { conditions: s, rules: [{ conditions: [q], rules: [{ endpoint: { url: "https://oidc.{Region}.{PartitionResult#dualStackDnsSuffix}", properties: n, headers: n }, type: e }], type: f }, { error: "DualStack is enabled but this partition does not support DualStack", type: d }], type: f }, { endpoint: { url: "https://oidc.{Region}.{PartitionResult#dnsSuffix}", properties: n, headers: n }, type: e }], type: f }], type: f }, { error: "Invalid Configuration: Missing Region", type: d }] };
exports.ruleSet = _data;


/***/ }),

/***/ 4527:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  AccessDeniedException: () => AccessDeniedException,
  AuthorizationPendingException: () => AuthorizationPendingException,
  CreateTokenCommand: () => CreateTokenCommand,
  CreateTokenRequestFilterSensitiveLog: () => CreateTokenRequestFilterSensitiveLog,
  CreateTokenResponseFilterSensitiveLog: () => CreateTokenResponseFilterSensitiveLog,
  CreateTokenWithIAMCommand: () => CreateTokenWithIAMCommand,
  CreateTokenWithIAMRequestFilterSensitiveLog: () => CreateTokenWithIAMRequestFilterSensitiveLog,
  CreateTokenWithIAMResponseFilterSensitiveLog: () => CreateTokenWithIAMResponseFilterSensitiveLog,
  ExpiredTokenException: () => ExpiredTokenException,
  InternalServerException: () => InternalServerException,
  InvalidClientException: () => InvalidClientException,
  InvalidClientMetadataException: () => InvalidClientMetadataException,
  InvalidGrantException: () => InvalidGrantException,
  InvalidRedirectUriException: () => InvalidRedirectUriException,
  InvalidRequestException: () => InvalidRequestException,
  InvalidRequestRegionException: () => InvalidRequestRegionException,
  InvalidScopeException: () => InvalidScopeException,
  RegisterClientCommand: () => RegisterClientCommand,
  RegisterClientResponseFilterSensitiveLog: () => RegisterClientResponseFilterSensitiveLog,
  SSOOIDC: () => SSOOIDC,
  SSOOIDCClient: () => SSOOIDCClient,
  SSOOIDCServiceException: () => SSOOIDCServiceException,
  SlowDownException: () => SlowDownException,
  StartDeviceAuthorizationCommand: () => StartDeviceAuthorizationCommand,
  StartDeviceAuthorizationRequestFilterSensitiveLog: () => StartDeviceAuthorizationRequestFilterSensitiveLog,
  UnauthorizedClientException: () => UnauthorizedClientException,
  UnsupportedGrantTypeException: () => UnsupportedGrantTypeException,
  __Client: () => import_smithy_client.Client
});
module.exports = __toCommonJS(src_exports);

// src/SSOOIDCClient.ts
var import_middleware_host_header = __nccwpck_require__(2545);
var import_middleware_logger = __nccwpck_require__(14);
var import_middleware_recursion_detection = __nccwpck_require__(5525);
var import_middleware_user_agent = __nccwpck_require__(4688);
var import_config_resolver = __nccwpck_require__(3098);
var import_core = __nccwpck_require__(5829);
var import_middleware_content_length = __nccwpck_require__(2800);
var import_middleware_endpoint = __nccwpck_require__(2918);
var import_middleware_retry = __nccwpck_require__(6039);

var import_httpAuthSchemeProvider = __nccwpck_require__(6948);

// src/endpoint/EndpointParameters.ts
var resolveClientEndpointParameters = /* @__PURE__ */ __name((options) => {
  return {
    ...options,
    useDualstackEndpoint: options.useDualstackEndpoint ?? false,
    useFipsEndpoint: options.useFipsEndpoint ?? false,
    defaultSigningName: "sso-oauth"
  };
}, "resolveClientEndpointParameters");
var commonParams = {
  UseFIPS: { type: "builtInParams", name: "useFipsEndpoint" },
  Endpoint: { type: "builtInParams", name: "endpoint" },
  Region: { type: "builtInParams", name: "region" },
  UseDualStack: { type: "builtInParams", name: "useDualstackEndpoint" }
};

// src/SSOOIDCClient.ts
var import_runtimeConfig = __nccwpck_require__(5524);

// src/runtimeExtensions.ts
var import_region_config_resolver = __nccwpck_require__(8156);
var import_protocol_http = __nccwpck_require__(4418);
var import_smithy_client = __nccwpck_require__(3570);

// src/auth/httpAuthExtensionConfiguration.ts
var getHttpAuthExtensionConfiguration = /* @__PURE__ */ __name((runtimeConfig) => {
  const _httpAuthSchemes = runtimeConfig.httpAuthSchemes;
  let _httpAuthSchemeProvider = runtimeConfig.httpAuthSchemeProvider;
  let _credentials = runtimeConfig.credentials;
  return {
    setHttpAuthScheme(httpAuthScheme) {
      const index = _httpAuthSchemes.findIndex((scheme) => scheme.schemeId === httpAuthScheme.schemeId);
      if (index === -1) {
        _httpAuthSchemes.push(httpAuthScheme);
      } else {
        _httpAuthSchemes.splice(index, 1, httpAuthScheme);
      }
    },
    httpAuthSchemes() {
      return _httpAuthSchemes;
    },
    setHttpAuthSchemeProvider(httpAuthSchemeProvider) {
      _httpAuthSchemeProvider = httpAuthSchemeProvider;
    },
    httpAuthSchemeProvider() {
      return _httpAuthSchemeProvider;
    },
    setCredentials(credentials) {
      _credentials = credentials;
    },
    credentials() {
      return _credentials;
    }
  };
}, "getHttpAuthExtensionConfiguration");
var resolveHttpAuthRuntimeConfig = /* @__PURE__ */ __name((config) => {
  return {
    httpAuthSchemes: config.httpAuthSchemes(),
    httpAuthSchemeProvider: config.httpAuthSchemeProvider(),
    credentials: config.credentials()
  };
}, "resolveHttpAuthRuntimeConfig");

// src/runtimeExtensions.ts
var asPartial = /* @__PURE__ */ __name((t) => t, "asPartial");
var resolveRuntimeExtensions = /* @__PURE__ */ __name((runtimeConfig, extensions) => {
  const extensionConfiguration = {
    ...asPartial((0, import_region_config_resolver.getAwsRegionExtensionConfiguration)(runtimeConfig)),
    ...asPartial((0, import_smithy_client.getDefaultExtensionConfiguration)(runtimeConfig)),
    ...asPartial((0, import_protocol_http.getHttpHandlerExtensionConfiguration)(runtimeConfig)),
    ...asPartial(getHttpAuthExtensionConfiguration(runtimeConfig))
  };
  extensions.forEach((extension) => extension.configure(extensionConfiguration));
  return {
    ...runtimeConfig,
    ...(0, import_region_config_resolver.resolveAwsRegionExtensionConfiguration)(extensionConfiguration),
    ...(0, import_smithy_client.resolveDefaultRuntimeConfig)(extensionConfiguration),
    ...(0, import_protocol_http.resolveHttpHandlerRuntimeConfig)(extensionConfiguration),
    ...resolveHttpAuthRuntimeConfig(extensionConfiguration)
  };
}, "resolveRuntimeExtensions");

// src/SSOOIDCClient.ts
var _SSOOIDCClient = class _SSOOIDCClient extends import_smithy_client.Client {
  constructor(...[configuration]) {
    const _config_0 = (0, import_runtimeConfig.getRuntimeConfig)(configuration || {});
    const _config_1 = resolveClientEndpointParameters(_config_0);
    const _config_2 = (0, import_middleware_user_agent.resolveUserAgentConfig)(_config_1);
    const _config_3 = (0, import_middleware_retry.resolveRetryConfig)(_config_2);
    const _config_4 = (0, import_config_resolver.resolveRegionConfig)(_config_3);
    const _config_5 = (0, import_middleware_host_header.resolveHostHeaderConfig)(_config_4);
    const _config_6 = (0, import_middleware_endpoint.resolveEndpointConfig)(_config_5);
    const _config_7 = (0, import_httpAuthSchemeProvider.resolveHttpAuthSchemeConfig)(_config_6);
    const _config_8 = resolveRuntimeExtensions(_config_7, (configuration == null ? void 0 : configuration.extensions) || []);
    super(_config_8);
    this.config = _config_8;
    this.middlewareStack.use((0, import_middleware_user_agent.getUserAgentPlugin)(this.config));
    this.middlewareStack.use((0, import_middleware_retry.getRetryPlugin)(this.config));
    this.middlewareStack.use((0, import_middleware_content_length.getContentLengthPlugin)(this.config));
    this.middlewareStack.use((0, import_middleware_host_header.getHostHeaderPlugin)(this.config));
    this.middlewareStack.use((0, import_middleware_logger.getLoggerPlugin)(this.config));
    this.middlewareStack.use((0, import_middleware_recursion_detection.getRecursionDetectionPlugin)(this.config));
    this.middlewareStack.use(
      (0, import_core.getHttpAuthSchemeEndpointRuleSetPlugin)(this.config, {
        httpAuthSchemeParametersProvider: import_httpAuthSchemeProvider.defaultSSOOIDCHttpAuthSchemeParametersProvider,
        identityProviderConfigProvider: async (config) => new import_core.DefaultIdentityProviderConfig({
          "aws.auth#sigv4": config.credentials
        })
      })
    );
    this.middlewareStack.use((0, import_core.getHttpSigningPlugin)(this.config));
  }
  /**
   * Destroy underlying resources, like sockets. It's usually not necessary to do this.
   * However in Node.js, it's best to explicitly shut down the client's agent when it is no longer needed.
   * Otherwise, sockets might stay open for quite a long time before the server terminates them.
   */
  destroy() {
    super.destroy();
  }
};
__name(_SSOOIDCClient, "SSOOIDCClient");
var SSOOIDCClient = _SSOOIDCClient;

// src/SSOOIDC.ts


// src/commands/CreateTokenCommand.ts

var import_middleware_serde = __nccwpck_require__(1238);


// src/models/models_0.ts


// src/models/SSOOIDCServiceException.ts

var _SSOOIDCServiceException = class _SSOOIDCServiceException extends import_smithy_client.ServiceException {
  /**
   * @internal
   */
  constructor(options) {
    super(options);
    Object.setPrototypeOf(this, _SSOOIDCServiceException.prototype);
  }
};
__name(_SSOOIDCServiceException, "SSOOIDCServiceException");
var SSOOIDCServiceException = _SSOOIDCServiceException;

// src/models/models_0.ts
var _AccessDeniedException = class _AccessDeniedException extends SSOOIDCServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "AccessDeniedException",
      $fault: "client",
      ...opts
    });
    this.name = "AccessDeniedException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _AccessDeniedException.prototype);
    this.error = opts.error;
    this.error_description = opts.error_description;
  }
};
__name(_AccessDeniedException, "AccessDeniedException");
var AccessDeniedException = _AccessDeniedException;
var _AuthorizationPendingException = class _AuthorizationPendingException extends SSOOIDCServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "AuthorizationPendingException",
      $fault: "client",
      ...opts
    });
    this.name = "AuthorizationPendingException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _AuthorizationPendingException.prototype);
    this.error = opts.error;
    this.error_description = opts.error_description;
  }
};
__name(_AuthorizationPendingException, "AuthorizationPendingException");
var AuthorizationPendingException = _AuthorizationPendingException;
var _ExpiredTokenException = class _ExpiredTokenException extends SSOOIDCServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "ExpiredTokenException",
      $fault: "client",
      ...opts
    });
    this.name = "ExpiredTokenException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _ExpiredTokenException.prototype);
    this.error = opts.error;
    this.error_description = opts.error_description;
  }
};
__name(_ExpiredTokenException, "ExpiredTokenException");
var ExpiredTokenException = _ExpiredTokenException;
var _InternalServerException = class _InternalServerException extends SSOOIDCServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "InternalServerException",
      $fault: "server",
      ...opts
    });
    this.name = "InternalServerException";
    this.$fault = "server";
    Object.setPrototypeOf(this, _InternalServerException.prototype);
    this.error = opts.error;
    this.error_description = opts.error_description;
  }
};
__name(_InternalServerException, "InternalServerException");
var InternalServerException = _InternalServerException;
var _InvalidClientException = class _InvalidClientException extends SSOOIDCServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "InvalidClientException",
      $fault: "client",
      ...opts
    });
    this.name = "InvalidClientException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _InvalidClientException.prototype);
    this.error = opts.error;
    this.error_description = opts.error_description;
  }
};
__name(_InvalidClientException, "InvalidClientException");
var InvalidClientException = _InvalidClientException;
var _InvalidGrantException = class _InvalidGrantException extends SSOOIDCServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "InvalidGrantException",
      $fault: "client",
      ...opts
    });
    this.name = "InvalidGrantException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _InvalidGrantException.prototype);
    this.error = opts.error;
    this.error_description = opts.error_description;
  }
};
__name(_InvalidGrantException, "InvalidGrantException");
var InvalidGrantException = _InvalidGrantException;
var _InvalidRequestException = class _InvalidRequestException extends SSOOIDCServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "InvalidRequestException",
      $fault: "client",
      ...opts
    });
    this.name = "InvalidRequestException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _InvalidRequestException.prototype);
    this.error = opts.error;
    this.error_description = opts.error_description;
  }
};
__name(_InvalidRequestException, "InvalidRequestException");
var InvalidRequestException = _InvalidRequestException;
var _InvalidScopeException = class _InvalidScopeException extends SSOOIDCServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "InvalidScopeException",
      $fault: "client",
      ...opts
    });
    this.name = "InvalidScopeException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _InvalidScopeException.prototype);
    this.error = opts.error;
    this.error_description = opts.error_description;
  }
};
__name(_InvalidScopeException, "InvalidScopeException");
var InvalidScopeException = _InvalidScopeException;
var _SlowDownException = class _SlowDownException extends SSOOIDCServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "SlowDownException",
      $fault: "client",
      ...opts
    });
    this.name = "SlowDownException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _SlowDownException.prototype);
    this.error = opts.error;
    this.error_description = opts.error_description;
  }
};
__name(_SlowDownException, "SlowDownException");
var SlowDownException = _SlowDownException;
var _UnauthorizedClientException = class _UnauthorizedClientException extends SSOOIDCServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "UnauthorizedClientException",
      $fault: "client",
      ...opts
    });
    this.name = "UnauthorizedClientException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _UnauthorizedClientException.prototype);
    this.error = opts.error;
    this.error_description = opts.error_description;
  }
};
__name(_UnauthorizedClientException, "UnauthorizedClientException");
var UnauthorizedClientException = _UnauthorizedClientException;
var _UnsupportedGrantTypeException = class _UnsupportedGrantTypeException extends SSOOIDCServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "UnsupportedGrantTypeException",
      $fault: "client",
      ...opts
    });
    this.name = "UnsupportedGrantTypeException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _UnsupportedGrantTypeException.prototype);
    this.error = opts.error;
    this.error_description = opts.error_description;
  }
};
__name(_UnsupportedGrantTypeException, "UnsupportedGrantTypeException");
var UnsupportedGrantTypeException = _UnsupportedGrantTypeException;
var _InvalidRequestRegionException = class _InvalidRequestRegionException extends SSOOIDCServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "InvalidRequestRegionException",
      $fault: "client",
      ...opts
    });
    this.name = "InvalidRequestRegionException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _InvalidRequestRegionException.prototype);
    this.error = opts.error;
    this.error_description = opts.error_description;
    this.endpoint = opts.endpoint;
    this.region = opts.region;
  }
};
__name(_InvalidRequestRegionException, "InvalidRequestRegionException");
var InvalidRequestRegionException = _InvalidRequestRegionException;
var _InvalidClientMetadataException = class _InvalidClientMetadataException extends SSOOIDCServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "InvalidClientMetadataException",
      $fault: "client",
      ...opts
    });
    this.name = "InvalidClientMetadataException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _InvalidClientMetadataException.prototype);
    this.error = opts.error;
    this.error_description = opts.error_description;
  }
};
__name(_InvalidClientMetadataException, "InvalidClientMetadataException");
var InvalidClientMetadataException = _InvalidClientMetadataException;
var _InvalidRedirectUriException = class _InvalidRedirectUriException extends SSOOIDCServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "InvalidRedirectUriException",
      $fault: "client",
      ...opts
    });
    this.name = "InvalidRedirectUriException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _InvalidRedirectUriException.prototype);
    this.error = opts.error;
    this.error_description = opts.error_description;
  }
};
__name(_InvalidRedirectUriException, "InvalidRedirectUriException");
var InvalidRedirectUriException = _InvalidRedirectUriException;
var CreateTokenRequestFilterSensitiveLog = /* @__PURE__ */ __name((obj) => ({
  ...obj,
  ...obj.clientSecret && { clientSecret: import_smithy_client.SENSITIVE_STRING },
  ...obj.refreshToken && { refreshToken: import_smithy_client.SENSITIVE_STRING },
  ...obj.codeVerifier && { codeVerifier: import_smithy_client.SENSITIVE_STRING }
}), "CreateTokenRequestFilterSensitiveLog");
var CreateTokenResponseFilterSensitiveLog = /* @__PURE__ */ __name((obj) => ({
  ...obj,
  ...obj.accessToken && { accessToken: import_smithy_client.SENSITIVE_STRING },
  ...obj.refreshToken && { refreshToken: import_smithy_client.SENSITIVE_STRING },
  ...obj.idToken && { idToken: import_smithy_client.SENSITIVE_STRING }
}), "CreateTokenResponseFilterSensitiveLog");
var CreateTokenWithIAMRequestFilterSensitiveLog = /* @__PURE__ */ __name((obj) => ({
  ...obj,
  ...obj.refreshToken && { refreshToken: import_smithy_client.SENSITIVE_STRING },
  ...obj.assertion && { assertion: import_smithy_client.SENSITIVE_STRING },
  ...obj.subjectToken && { subjectToken: import_smithy_client.SENSITIVE_STRING },
  ...obj.codeVerifier && { codeVerifier: import_smithy_client.SENSITIVE_STRING }
}), "CreateTokenWithIAMRequestFilterSensitiveLog");
var CreateTokenWithIAMResponseFilterSensitiveLog = /* @__PURE__ */ __name((obj) => ({
  ...obj,
  ...obj.accessToken && { accessToken: import_smithy_client.SENSITIVE_STRING },
  ...obj.refreshToken && { refreshToken: import_smithy_client.SENSITIVE_STRING },
  ...obj.idToken && { idToken: import_smithy_client.SENSITIVE_STRING }
}), "CreateTokenWithIAMResponseFilterSensitiveLog");
var RegisterClientResponseFilterSensitiveLog = /* @__PURE__ */ __name((obj) => ({
  ...obj,
  ...obj.clientSecret && { clientSecret: import_smithy_client.SENSITIVE_STRING }
}), "RegisterClientResponseFilterSensitiveLog");
var StartDeviceAuthorizationRequestFilterSensitiveLog = /* @__PURE__ */ __name((obj) => ({
  ...obj,
  ...obj.clientSecret && { clientSecret: import_smithy_client.SENSITIVE_STRING }
}), "StartDeviceAuthorizationRequestFilterSensitiveLog");

// src/protocols/Aws_restJson1.ts
var import_core2 = __nccwpck_require__(9963);


var se_CreateTokenCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/token");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      clientId: [],
      clientSecret: [],
      code: [],
      codeVerifier: [],
      deviceCode: [],
      grantType: [],
      redirectUri: [],
      refreshToken: [],
      scope: (_) => (0, import_smithy_client._json)(_)
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_CreateTokenCommand");
var se_CreateTokenWithIAMCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/token");
  const query = (0, import_smithy_client.map)({
    [_ai]: [, "t"]
  });
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      assertion: [],
      clientId: [],
      code: [],
      codeVerifier: [],
      grantType: [],
      redirectUri: [],
      refreshToken: [],
      requestedTokenType: [],
      scope: (_) => (0, import_smithy_client._json)(_),
      subjectToken: [],
      subjectTokenType: []
    })
  );
  b.m("POST").h(headers).q(query).b(body);
  return b.build();
}, "se_CreateTokenWithIAMCommand");
var se_RegisterClientCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/client/register");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      clientName: [],
      clientType: [],
      entitledApplicationArn: [],
      grantTypes: (_) => (0, import_smithy_client._json)(_),
      issuerUrl: [],
      redirectUris: (_) => (0, import_smithy_client._json)(_),
      scopes: (_) => (0, import_smithy_client._json)(_)
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_RegisterClientCommand");
var se_StartDeviceAuthorizationCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b.bp("/device_authorization");
  let body;
  body = JSON.stringify(
    (0, import_smithy_client.take)(input, {
      clientId: [],
      clientSecret: [],
      startUrl: []
    })
  );
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_StartDeviceAuthorizationCommand");
var de_CreateTokenCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    accessToken: import_smithy_client.expectString,
    expiresIn: import_smithy_client.expectInt32,
    idToken: import_smithy_client.expectString,
    refreshToken: import_smithy_client.expectString,
    tokenType: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  return contents;
}, "de_CreateTokenCommand");
var de_CreateTokenWithIAMCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    accessToken: import_smithy_client.expectString,
    expiresIn: import_smithy_client.expectInt32,
    idToken: import_smithy_client.expectString,
    issuedTokenType: import_smithy_client.expectString,
    refreshToken: import_smithy_client.expectString,
    scope: import_smithy_client._json,
    tokenType: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  return contents;
}, "de_CreateTokenWithIAMCommand");
var de_RegisterClientCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    authorizationEndpoint: import_smithy_client.expectString,
    clientId: import_smithy_client.expectString,
    clientIdIssuedAt: import_smithy_client.expectLong,
    clientSecret: import_smithy_client.expectString,
    clientSecretExpiresAt: import_smithy_client.expectLong,
    tokenEndpoint: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  return contents;
}, "de_RegisterClientCommand");
var de_StartDeviceAuthorizationCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    deviceCode: import_smithy_client.expectString,
    expiresIn: import_smithy_client.expectInt32,
    interval: import_smithy_client.expectInt32,
    userCode: import_smithy_client.expectString,
    verificationUri: import_smithy_client.expectString,
    verificationUriComplete: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  return contents;
}, "de_StartDeviceAuthorizationCommand");
var de_CommandError = /* @__PURE__ */ __name(async (output, context) => {
  const parsedOutput = {
    ...output,
    body: await (0, import_core2.parseJsonErrorBody)(output.body, context)
  };
  const errorCode = (0, import_core2.loadRestJsonErrorCode)(output, parsedOutput.body);
  switch (errorCode) {
    case "AccessDeniedException":
    case "com.amazonaws.ssooidc#AccessDeniedException":
      throw await de_AccessDeniedExceptionRes(parsedOutput, context);
    case "AuthorizationPendingException":
    case "com.amazonaws.ssooidc#AuthorizationPendingException":
      throw await de_AuthorizationPendingExceptionRes(parsedOutput, context);
    case "ExpiredTokenException":
    case "com.amazonaws.ssooidc#ExpiredTokenException":
      throw await de_ExpiredTokenExceptionRes(parsedOutput, context);
    case "InternalServerException":
    case "com.amazonaws.ssooidc#InternalServerException":
      throw await de_InternalServerExceptionRes(parsedOutput, context);
    case "InvalidClientException":
    case "com.amazonaws.ssooidc#InvalidClientException":
      throw await de_InvalidClientExceptionRes(parsedOutput, context);
    case "InvalidGrantException":
    case "com.amazonaws.ssooidc#InvalidGrantException":
      throw await de_InvalidGrantExceptionRes(parsedOutput, context);
    case "InvalidRequestException":
    case "com.amazonaws.ssooidc#InvalidRequestException":
      throw await de_InvalidRequestExceptionRes(parsedOutput, context);
    case "InvalidScopeException":
    case "com.amazonaws.ssooidc#InvalidScopeException":
      throw await de_InvalidScopeExceptionRes(parsedOutput, context);
    case "SlowDownException":
    case "com.amazonaws.ssooidc#SlowDownException":
      throw await de_SlowDownExceptionRes(parsedOutput, context);
    case "UnauthorizedClientException":
    case "com.amazonaws.ssooidc#UnauthorizedClientException":
      throw await de_UnauthorizedClientExceptionRes(parsedOutput, context);
    case "UnsupportedGrantTypeException":
    case "com.amazonaws.ssooidc#UnsupportedGrantTypeException":
      throw await de_UnsupportedGrantTypeExceptionRes(parsedOutput, context);
    case "InvalidRequestRegionException":
    case "com.amazonaws.ssooidc#InvalidRequestRegionException":
      throw await de_InvalidRequestRegionExceptionRes(parsedOutput, context);
    case "InvalidClientMetadataException":
    case "com.amazonaws.ssooidc#InvalidClientMetadataException":
      throw await de_InvalidClientMetadataExceptionRes(parsedOutput, context);
    case "InvalidRedirectUriException":
    case "com.amazonaws.ssooidc#InvalidRedirectUriException":
      throw await de_InvalidRedirectUriExceptionRes(parsedOutput, context);
    default:
      const parsedBody = parsedOutput.body;
      return throwDefaultError({
        output,
        parsedBody,
        errorCode
      });
  }
}, "de_CommandError");
var throwDefaultError = (0, import_smithy_client.withBaseException)(SSOOIDCServiceException);
var de_AccessDeniedExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const contents = (0, import_smithy_client.map)({});
  const data = parsedOutput.body;
  const doc = (0, import_smithy_client.take)(data, {
    error: import_smithy_client.expectString,
    error_description: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  const exception = new AccessDeniedException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return (0, import_smithy_client.decorateServiceException)(exception, parsedOutput.body);
}, "de_AccessDeniedExceptionRes");
var de_AuthorizationPendingExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const contents = (0, import_smithy_client.map)({});
  const data = parsedOutput.body;
  const doc = (0, import_smithy_client.take)(data, {
    error: import_smithy_client.expectString,
    error_description: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  const exception = new AuthorizationPendingException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return (0, import_smithy_client.decorateServiceException)(exception, parsedOutput.body);
}, "de_AuthorizationPendingExceptionRes");
var de_ExpiredTokenExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const contents = (0, import_smithy_client.map)({});
  const data = parsedOutput.body;
  const doc = (0, import_smithy_client.take)(data, {
    error: import_smithy_client.expectString,
    error_description: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  const exception = new ExpiredTokenException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return (0, import_smithy_client.decorateServiceException)(exception, parsedOutput.body);
}, "de_ExpiredTokenExceptionRes");
var de_InternalServerExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const contents = (0, import_smithy_client.map)({});
  const data = parsedOutput.body;
  const doc = (0, import_smithy_client.take)(data, {
    error: import_smithy_client.expectString,
    error_description: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  const exception = new InternalServerException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return (0, import_smithy_client.decorateServiceException)(exception, parsedOutput.body);
}, "de_InternalServerExceptionRes");
var de_InvalidClientExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const contents = (0, import_smithy_client.map)({});
  const data = parsedOutput.body;
  const doc = (0, import_smithy_client.take)(data, {
    error: import_smithy_client.expectString,
    error_description: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  const exception = new InvalidClientException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return (0, import_smithy_client.decorateServiceException)(exception, parsedOutput.body);
}, "de_InvalidClientExceptionRes");
var de_InvalidClientMetadataExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const contents = (0, import_smithy_client.map)({});
  const data = parsedOutput.body;
  const doc = (0, import_smithy_client.take)(data, {
    error: import_smithy_client.expectString,
    error_description: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  const exception = new InvalidClientMetadataException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return (0, import_smithy_client.decorateServiceException)(exception, parsedOutput.body);
}, "de_InvalidClientMetadataExceptionRes");
var de_InvalidGrantExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const contents = (0, import_smithy_client.map)({});
  const data = parsedOutput.body;
  const doc = (0, import_smithy_client.take)(data, {
    error: import_smithy_client.expectString,
    error_description: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  const exception = new InvalidGrantException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return (0, import_smithy_client.decorateServiceException)(exception, parsedOutput.body);
}, "de_InvalidGrantExceptionRes");
var de_InvalidRedirectUriExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const contents = (0, import_smithy_client.map)({});
  const data = parsedOutput.body;
  const doc = (0, import_smithy_client.take)(data, {
    error: import_smithy_client.expectString,
    error_description: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  const exception = new InvalidRedirectUriException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return (0, import_smithy_client.decorateServiceException)(exception, parsedOutput.body);
}, "de_InvalidRedirectUriExceptionRes");
var de_InvalidRequestExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const contents = (0, import_smithy_client.map)({});
  const data = parsedOutput.body;
  const doc = (0, import_smithy_client.take)(data, {
    error: import_smithy_client.expectString,
    error_description: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  const exception = new InvalidRequestException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return (0, import_smithy_client.decorateServiceException)(exception, parsedOutput.body);
}, "de_InvalidRequestExceptionRes");
var de_InvalidRequestRegionExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const contents = (0, import_smithy_client.map)({});
  const data = parsedOutput.body;
  const doc = (0, import_smithy_client.take)(data, {
    endpoint: import_smithy_client.expectString,
    error: import_smithy_client.expectString,
    error_description: import_smithy_client.expectString,
    region: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  const exception = new InvalidRequestRegionException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return (0, import_smithy_client.decorateServiceException)(exception, parsedOutput.body);
}, "de_InvalidRequestRegionExceptionRes");
var de_InvalidScopeExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const contents = (0, import_smithy_client.map)({});
  const data = parsedOutput.body;
  const doc = (0, import_smithy_client.take)(data, {
    error: import_smithy_client.expectString,
    error_description: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  const exception = new InvalidScopeException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return (0, import_smithy_client.decorateServiceException)(exception, parsedOutput.body);
}, "de_InvalidScopeExceptionRes");
var de_SlowDownExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const contents = (0, import_smithy_client.map)({});
  const data = parsedOutput.body;
  const doc = (0, import_smithy_client.take)(data, {
    error: import_smithy_client.expectString,
    error_description: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  const exception = new SlowDownException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return (0, import_smithy_client.decorateServiceException)(exception, parsedOutput.body);
}, "de_SlowDownExceptionRes");
var de_UnauthorizedClientExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const contents = (0, import_smithy_client.map)({});
  const data = parsedOutput.body;
  const doc = (0, import_smithy_client.take)(data, {
    error: import_smithy_client.expectString,
    error_description: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  const exception = new UnauthorizedClientException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return (0, import_smithy_client.decorateServiceException)(exception, parsedOutput.body);
}, "de_UnauthorizedClientExceptionRes");
var de_UnsupportedGrantTypeExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const contents = (0, import_smithy_client.map)({});
  const data = parsedOutput.body;
  const doc = (0, import_smithy_client.take)(data, {
    error: import_smithy_client.expectString,
    error_description: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  const exception = new UnsupportedGrantTypeException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return (0, import_smithy_client.decorateServiceException)(exception, parsedOutput.body);
}, "de_UnsupportedGrantTypeExceptionRes");
var deserializeMetadata = /* @__PURE__ */ __name((output) => ({
  httpStatusCode: output.statusCode,
  requestId: output.headers["x-amzn-requestid"] ?? output.headers["x-amzn-request-id"] ?? output.headers["x-amz-request-id"],
  extendedRequestId: output.headers["x-amz-id-2"],
  cfId: output.headers["x-amz-cf-id"]
}), "deserializeMetadata");
var _ai = "aws_iam";

// src/commands/CreateTokenCommand.ts
var _CreateTokenCommand = class _CreateTokenCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AWSSSOOIDCService", "CreateToken", {}).n("SSOOIDCClient", "CreateTokenCommand").f(CreateTokenRequestFilterSensitiveLog, CreateTokenResponseFilterSensitiveLog).ser(se_CreateTokenCommand).de(de_CreateTokenCommand).build() {
};
__name(_CreateTokenCommand, "CreateTokenCommand");
var CreateTokenCommand = _CreateTokenCommand;

// src/commands/CreateTokenWithIAMCommand.ts



var _CreateTokenWithIAMCommand = class _CreateTokenWithIAMCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AWSSSOOIDCService", "CreateTokenWithIAM", {}).n("SSOOIDCClient", "CreateTokenWithIAMCommand").f(CreateTokenWithIAMRequestFilterSensitiveLog, CreateTokenWithIAMResponseFilterSensitiveLog).ser(se_CreateTokenWithIAMCommand).de(de_CreateTokenWithIAMCommand).build() {
};
__name(_CreateTokenWithIAMCommand, "CreateTokenWithIAMCommand");
var CreateTokenWithIAMCommand = _CreateTokenWithIAMCommand;

// src/commands/RegisterClientCommand.ts



var _RegisterClientCommand = class _RegisterClientCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AWSSSOOIDCService", "RegisterClient", {}).n("SSOOIDCClient", "RegisterClientCommand").f(void 0, RegisterClientResponseFilterSensitiveLog).ser(se_RegisterClientCommand).de(de_RegisterClientCommand).build() {
};
__name(_RegisterClientCommand, "RegisterClientCommand");
var RegisterClientCommand = _RegisterClientCommand;

// src/commands/StartDeviceAuthorizationCommand.ts



var _StartDeviceAuthorizationCommand = class _StartDeviceAuthorizationCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AWSSSOOIDCService", "StartDeviceAuthorization", {}).n("SSOOIDCClient", "StartDeviceAuthorizationCommand").f(StartDeviceAuthorizationRequestFilterSensitiveLog, void 0).ser(se_StartDeviceAuthorizationCommand).de(de_StartDeviceAuthorizationCommand).build() {
};
__name(_StartDeviceAuthorizationCommand, "StartDeviceAuthorizationCommand");
var StartDeviceAuthorizationCommand = _StartDeviceAuthorizationCommand;

// src/SSOOIDC.ts
var commands = {
  CreateTokenCommand,
  CreateTokenWithIAMCommand,
  RegisterClientCommand,
  StartDeviceAuthorizationCommand
};
var _SSOOIDC = class _SSOOIDC extends SSOOIDCClient {
};
__name(_SSOOIDC, "SSOOIDC");
var SSOOIDC = _SSOOIDC;
(0, import_smithy_client.createAggregatedClient)(commands, SSOOIDC);
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 5524:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.getRuntimeConfig = void 0;
const tslib_1 = __nccwpck_require__(4351);
const package_json_1 = tslib_1.__importDefault(__nccwpck_require__(9722));
const core_1 = __nccwpck_require__(9963);
const credential_provider_node_1 = __nccwpck_require__(5531);
const util_user_agent_node_1 = __nccwpck_require__(8095);
const config_resolver_1 = __nccwpck_require__(3098);
const hash_node_1 = __nccwpck_require__(3081);
const middleware_retry_1 = __nccwpck_require__(6039);
const node_config_provider_1 = __nccwpck_require__(3461);
const node_http_handler_1 = __nccwpck_require__(258);
const util_body_length_node_1 = __nccwpck_require__(8075);
const util_retry_1 = __nccwpck_require__(4902);
const runtimeConfig_shared_1 = __nccwpck_require__(8005);
const smithy_client_1 = __nccwpck_require__(3570);
const util_defaults_mode_node_1 = __nccwpck_require__(2429);
const smithy_client_2 = __nccwpck_require__(3570);
const getRuntimeConfig = (config) => {
    (0, smithy_client_2.emitWarningIfUnsupportedVersion)(process.version);
    const defaultsMode = (0, util_defaults_mode_node_1.resolveDefaultsModeConfig)(config);
    const defaultConfigProvider = () => defaultsMode().then(smithy_client_1.loadConfigsForDefaultMode);
    const clientSharedValues = (0, runtimeConfig_shared_1.getRuntimeConfig)(config);
    (0, core_1.emitWarningIfUnsupportedVersion)(process.version);
    return {
        ...clientSharedValues,
        ...config,
        runtime: "node",
        defaultsMode,
        bodyLengthChecker: config?.bodyLengthChecker ?? util_body_length_node_1.calculateBodyLength,
        credentialDefaultProvider: config?.credentialDefaultProvider ?? credential_provider_node_1.defaultProvider,
        defaultUserAgentProvider: config?.defaultUserAgentProvider ??
            (0, util_user_agent_node_1.defaultUserAgent)({ serviceId: clientSharedValues.serviceId, clientVersion: package_json_1.default.version }),
        maxAttempts: config?.maxAttempts ?? (0, node_config_provider_1.loadConfig)(middleware_retry_1.NODE_MAX_ATTEMPT_CONFIG_OPTIONS),
        region: config?.region ?? (0, node_config_provider_1.loadConfig)(config_resolver_1.NODE_REGION_CONFIG_OPTIONS, config_resolver_1.NODE_REGION_CONFIG_FILE_OPTIONS),
        requestHandler: node_http_handler_1.NodeHttpHandler.create(config?.requestHandler ?? defaultConfigProvider),
        retryMode: config?.retryMode ??
            (0, node_config_provider_1.loadConfig)({
                ...middleware_retry_1.NODE_RETRY_MODE_CONFIG_OPTIONS,
                default: async () => (await defaultConfigProvider()).retryMode || util_retry_1.DEFAULT_RETRY_MODE,
            }),
        sha256: config?.sha256 ?? hash_node_1.Hash.bind(null, "sha256"),
        streamCollector: config?.streamCollector ?? node_http_handler_1.streamCollector,
        useDualstackEndpoint: config?.useDualstackEndpoint ?? (0, node_config_provider_1.loadConfig)(config_resolver_1.NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS),
        useFipsEndpoint: config?.useFipsEndpoint ?? (0, node_config_provider_1.loadConfig)(config_resolver_1.NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS),
    };
};
exports.getRuntimeConfig = getRuntimeConfig;


/***/ }),

/***/ 8005:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.getRuntimeConfig = void 0;
const core_1 = __nccwpck_require__(9963);
const core_2 = __nccwpck_require__(5829);
const smithy_client_1 = __nccwpck_require__(3570);
const url_parser_1 = __nccwpck_require__(4681);
const util_base64_1 = __nccwpck_require__(5600);
const util_utf8_1 = __nccwpck_require__(1895);
const httpAuthSchemeProvider_1 = __nccwpck_require__(6948);
const endpointResolver_1 = __nccwpck_require__(7604);
const getRuntimeConfig = (config) => {
    return {
        apiVersion: "2019-06-10",
        base64Decoder: config?.base64Decoder ?? util_base64_1.fromBase64,
        base64Encoder: config?.base64Encoder ?? util_base64_1.toBase64,
        disableHostPrefix: config?.disableHostPrefix ?? false,
        endpointProvider: config?.endpointProvider ?? endpointResolver_1.defaultEndpointResolver,
        extensions: config?.extensions ?? [],
        httpAuthSchemeProvider: config?.httpAuthSchemeProvider ?? httpAuthSchemeProvider_1.defaultSSOOIDCHttpAuthSchemeProvider,
        httpAuthSchemes: config?.httpAuthSchemes ?? [
            {
                schemeId: "aws.auth#sigv4",
                identityProvider: (ipc) => ipc.getIdentityProvider("aws.auth#sigv4"),
                signer: new core_1.AwsSdkSigV4Signer(),
            },
            {
                schemeId: "smithy.api#noAuth",
                identityProvider: (ipc) => ipc.getIdentityProvider("smithy.api#noAuth") || (async () => ({})),
                signer: new core_2.NoAuthSigner(),
            },
        ],
        logger: config?.logger ?? new smithy_client_1.NoOpLogger(),
        serviceId: config?.serviceId ?? "SSO OIDC",
        urlParser: config?.urlParser ?? url_parser_1.parseUrl,
        utf8Decoder: config?.utf8Decoder ?? util_utf8_1.fromUtf8,
        utf8Encoder: config?.utf8Encoder ?? util_utf8_1.toUtf8,
    };
};
exports.getRuntimeConfig = getRuntimeConfig;


/***/ }),

/***/ 9344:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.resolveHttpAuthSchemeConfig = exports.defaultSSOHttpAuthSchemeProvider = exports.defaultSSOHttpAuthSchemeParametersProvider = void 0;
const core_1 = __nccwpck_require__(9963);
const util_middleware_1 = __nccwpck_require__(2390);
const defaultSSOHttpAuthSchemeParametersProvider = async (config, context, input) => {
    return {
        operation: (0, util_middleware_1.getSmithyContext)(context).operation,
        region: (await (0, util_middleware_1.normalizeProvider)(config.region)()) ||
            (() => {
                throw new Error("expected `region` to be configured for `aws.auth#sigv4`");
            })(),
    };
};
exports.defaultSSOHttpAuthSchemeParametersProvider = defaultSSOHttpAuthSchemeParametersProvider;
function createAwsAuthSigv4HttpAuthOption(authParameters) {
    return {
        schemeId: "aws.auth#sigv4",
        signingProperties: {
            name: "awsssoportal",
            region: authParameters.region,
        },
        propertiesExtractor: (config, context) => ({
            signingProperties: {
                config,
                context,
            },
        }),
    };
}
function createSmithyApiNoAuthHttpAuthOption(authParameters) {
    return {
        schemeId: "smithy.api#noAuth",
    };
}
const defaultSSOHttpAuthSchemeProvider = (authParameters) => {
    const options = [];
    switch (authParameters.operation) {
        case "GetRoleCredentials": {
            options.push(createSmithyApiNoAuthHttpAuthOption(authParameters));
            break;
        }
        case "ListAccountRoles": {
            options.push(createSmithyApiNoAuthHttpAuthOption(authParameters));
            break;
        }
        case "ListAccounts": {
            options.push(createSmithyApiNoAuthHttpAuthOption(authParameters));
            break;
        }
        case "Logout": {
            options.push(createSmithyApiNoAuthHttpAuthOption(authParameters));
            break;
        }
        default: {
            options.push(createAwsAuthSigv4HttpAuthOption(authParameters));
        }
    }
    return options;
};
exports.defaultSSOHttpAuthSchemeProvider = defaultSSOHttpAuthSchemeProvider;
const resolveHttpAuthSchemeConfig = (config) => {
    const config_0 = (0, core_1.resolveAwsSdkSigV4Config)(config);
    return {
        ...config_0,
    };
};
exports.resolveHttpAuthSchemeConfig = resolveHttpAuthSchemeConfig;


/***/ }),

/***/ 898:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.defaultEndpointResolver = void 0;
const util_endpoints_1 = __nccwpck_require__(3350);
const util_endpoints_2 = __nccwpck_require__(5473);
const ruleset_1 = __nccwpck_require__(3341);
const defaultEndpointResolver = (endpointParams, context = {}) => {
    return (0, util_endpoints_2.resolveEndpoint)(ruleset_1.ruleSet, {
        endpointParams: endpointParams,
        logger: context.logger,
    });
};
exports.defaultEndpointResolver = defaultEndpointResolver;
util_endpoints_2.customEndpointFunctions.aws = util_endpoints_1.awsEndpointFunctions;


/***/ }),

/***/ 3341:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ruleSet = void 0;
const u = "required", v = "fn", w = "argv", x = "ref";
const a = true, b = "isSet", c = "booleanEquals", d = "error", e = "endpoint", f = "tree", g = "PartitionResult", h = "getAttr", i = { [u]: false, "type": "String" }, j = { [u]: true, "default": false, "type": "Boolean" }, k = { [x]: "Endpoint" }, l = { [v]: c, [w]: [{ [x]: "UseFIPS" }, true] }, m = { [v]: c, [w]: [{ [x]: "UseDualStack" }, true] }, n = {}, o = { [v]: h, [w]: [{ [x]: g }, "supportsFIPS"] }, p = { [x]: g }, q = { [v]: c, [w]: [true, { [v]: h, [w]: [p, "supportsDualStack"] }] }, r = [l], s = [m], t = [{ [x]: "Region" }];
const _data = { version: "1.0", parameters: { Region: i, UseDualStack: j, UseFIPS: j, Endpoint: i }, rules: [{ conditions: [{ [v]: b, [w]: [k] }], rules: [{ conditions: r, error: "Invalid Configuration: FIPS and custom endpoint are not supported", type: d }, { conditions: s, error: "Invalid Configuration: Dualstack and custom endpoint are not supported", type: d }, { endpoint: { url: k, properties: n, headers: n }, type: e }], type: f }, { conditions: [{ [v]: b, [w]: t }], rules: [{ conditions: [{ [v]: "aws.partition", [w]: t, assign: g }], rules: [{ conditions: [l, m], rules: [{ conditions: [{ [v]: c, [w]: [a, o] }, q], rules: [{ endpoint: { url: "https://portal.sso-fips.{Region}.{PartitionResult#dualStackDnsSuffix}", properties: n, headers: n }, type: e }], type: f }, { error: "FIPS and DualStack are enabled, but this partition does not support one or both", type: d }], type: f }, { conditions: r, rules: [{ conditions: [{ [v]: c, [w]: [o, a] }], rules: [{ conditions: [{ [v]: "stringEquals", [w]: [{ [v]: h, [w]: [p, "name"] }, "aws-us-gov"] }], endpoint: { url: "https://portal.sso.{Region}.amazonaws.com", properties: n, headers: n }, type: e }, { endpoint: { url: "https://portal.sso-fips.{Region}.{PartitionResult#dnsSuffix}", properties: n, headers: n }, type: e }], type: f }, { error: "FIPS is enabled but this partition does not support FIPS", type: d }], type: f }, { conditions: s, rules: [{ conditions: [q], rules: [{ endpoint: { url: "https://portal.sso.{Region}.{PartitionResult#dualStackDnsSuffix}", properties: n, headers: n }, type: e }], type: f }, { error: "DualStack is enabled but this partition does not support DualStack", type: d }], type: f }, { endpoint: { url: "https://portal.sso.{Region}.{PartitionResult#dnsSuffix}", properties: n, headers: n }, type: e }], type: f }], type: f }, { error: "Invalid Configuration: Missing Region", type: d }] };
exports.ruleSet = _data;


/***/ }),

/***/ 2666:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  GetRoleCredentialsCommand: () => GetRoleCredentialsCommand,
  GetRoleCredentialsRequestFilterSensitiveLog: () => GetRoleCredentialsRequestFilterSensitiveLog,
  GetRoleCredentialsResponseFilterSensitiveLog: () => GetRoleCredentialsResponseFilterSensitiveLog,
  InvalidRequestException: () => InvalidRequestException,
  ListAccountRolesCommand: () => ListAccountRolesCommand,
  ListAccountRolesRequestFilterSensitiveLog: () => ListAccountRolesRequestFilterSensitiveLog,
  ListAccountsCommand: () => ListAccountsCommand,
  ListAccountsRequestFilterSensitiveLog: () => ListAccountsRequestFilterSensitiveLog,
  LogoutCommand: () => LogoutCommand,
  LogoutRequestFilterSensitiveLog: () => LogoutRequestFilterSensitiveLog,
  ResourceNotFoundException: () => ResourceNotFoundException,
  RoleCredentialsFilterSensitiveLog: () => RoleCredentialsFilterSensitiveLog,
  SSO: () => SSO,
  SSOClient: () => SSOClient,
  SSOServiceException: () => SSOServiceException,
  TooManyRequestsException: () => TooManyRequestsException,
  UnauthorizedException: () => UnauthorizedException,
  __Client: () => import_smithy_client.Client,
  paginateListAccountRoles: () => paginateListAccountRoles,
  paginateListAccounts: () => paginateListAccounts
});
module.exports = __toCommonJS(src_exports);

// src/SSOClient.ts
var import_middleware_host_header = __nccwpck_require__(2545);
var import_middleware_logger = __nccwpck_require__(14);
var import_middleware_recursion_detection = __nccwpck_require__(5525);
var import_middleware_user_agent = __nccwpck_require__(4688);
var import_config_resolver = __nccwpck_require__(3098);
var import_core = __nccwpck_require__(5829);
var import_middleware_content_length = __nccwpck_require__(2800);
var import_middleware_endpoint = __nccwpck_require__(2918);
var import_middleware_retry = __nccwpck_require__(6039);

var import_httpAuthSchemeProvider = __nccwpck_require__(9344);

// src/endpoint/EndpointParameters.ts
var resolveClientEndpointParameters = /* @__PURE__ */ __name((options) => {
  return {
    ...options,
    useDualstackEndpoint: options.useDualstackEndpoint ?? false,
    useFipsEndpoint: options.useFipsEndpoint ?? false,
    defaultSigningName: "awsssoportal"
  };
}, "resolveClientEndpointParameters");
var commonParams = {
  UseFIPS: { type: "builtInParams", name: "useFipsEndpoint" },
  Endpoint: { type: "builtInParams", name: "endpoint" },
  Region: { type: "builtInParams", name: "region" },
  UseDualStack: { type: "builtInParams", name: "useDualstackEndpoint" }
};

// src/SSOClient.ts
var import_runtimeConfig = __nccwpck_require__(9756);

// src/runtimeExtensions.ts
var import_region_config_resolver = __nccwpck_require__(8156);
var import_protocol_http = __nccwpck_require__(4418);
var import_smithy_client = __nccwpck_require__(3570);

// src/auth/httpAuthExtensionConfiguration.ts
var getHttpAuthExtensionConfiguration = /* @__PURE__ */ __name((runtimeConfig) => {
  const _httpAuthSchemes = runtimeConfig.httpAuthSchemes;
  let _httpAuthSchemeProvider = runtimeConfig.httpAuthSchemeProvider;
  let _credentials = runtimeConfig.credentials;
  return {
    setHttpAuthScheme(httpAuthScheme) {
      const index = _httpAuthSchemes.findIndex((scheme) => scheme.schemeId === httpAuthScheme.schemeId);
      if (index === -1) {
        _httpAuthSchemes.push(httpAuthScheme);
      } else {
        _httpAuthSchemes.splice(index, 1, httpAuthScheme);
      }
    },
    httpAuthSchemes() {
      return _httpAuthSchemes;
    },
    setHttpAuthSchemeProvider(httpAuthSchemeProvider) {
      _httpAuthSchemeProvider = httpAuthSchemeProvider;
    },
    httpAuthSchemeProvider() {
      return _httpAuthSchemeProvider;
    },
    setCredentials(credentials) {
      _credentials = credentials;
    },
    credentials() {
      return _credentials;
    }
  };
}, "getHttpAuthExtensionConfiguration");
var resolveHttpAuthRuntimeConfig = /* @__PURE__ */ __name((config) => {
  return {
    httpAuthSchemes: config.httpAuthSchemes(),
    httpAuthSchemeProvider: config.httpAuthSchemeProvider(),
    credentials: config.credentials()
  };
}, "resolveHttpAuthRuntimeConfig");

// src/runtimeExtensions.ts
var asPartial = /* @__PURE__ */ __name((t) => t, "asPartial");
var resolveRuntimeExtensions = /* @__PURE__ */ __name((runtimeConfig, extensions) => {
  const extensionConfiguration = {
    ...asPartial((0, import_region_config_resolver.getAwsRegionExtensionConfiguration)(runtimeConfig)),
    ...asPartial((0, import_smithy_client.getDefaultExtensionConfiguration)(runtimeConfig)),
    ...asPartial((0, import_protocol_http.getHttpHandlerExtensionConfiguration)(runtimeConfig)),
    ...asPartial(getHttpAuthExtensionConfiguration(runtimeConfig))
  };
  extensions.forEach((extension) => extension.configure(extensionConfiguration));
  return {
    ...runtimeConfig,
    ...(0, import_region_config_resolver.resolveAwsRegionExtensionConfiguration)(extensionConfiguration),
    ...(0, import_smithy_client.resolveDefaultRuntimeConfig)(extensionConfiguration),
    ...(0, import_protocol_http.resolveHttpHandlerRuntimeConfig)(extensionConfiguration),
    ...resolveHttpAuthRuntimeConfig(extensionConfiguration)
  };
}, "resolveRuntimeExtensions");

// src/SSOClient.ts
var _SSOClient = class _SSOClient extends import_smithy_client.Client {
  constructor(...[configuration]) {
    const _config_0 = (0, import_runtimeConfig.getRuntimeConfig)(configuration || {});
    const _config_1 = resolveClientEndpointParameters(_config_0);
    const _config_2 = (0, import_middleware_user_agent.resolveUserAgentConfig)(_config_1);
    const _config_3 = (0, import_middleware_retry.resolveRetryConfig)(_config_2);
    const _config_4 = (0, import_config_resolver.resolveRegionConfig)(_config_3);
    const _config_5 = (0, import_middleware_host_header.resolveHostHeaderConfig)(_config_4);
    const _config_6 = (0, import_middleware_endpoint.resolveEndpointConfig)(_config_5);
    const _config_7 = (0, import_httpAuthSchemeProvider.resolveHttpAuthSchemeConfig)(_config_6);
    const _config_8 = resolveRuntimeExtensions(_config_7, (configuration == null ? void 0 : configuration.extensions) || []);
    super(_config_8);
    this.config = _config_8;
    this.middlewareStack.use((0, import_middleware_user_agent.getUserAgentPlugin)(this.config));
    this.middlewareStack.use((0, import_middleware_retry.getRetryPlugin)(this.config));
    this.middlewareStack.use((0, import_middleware_content_length.getContentLengthPlugin)(this.config));
    this.middlewareStack.use((0, import_middleware_host_header.getHostHeaderPlugin)(this.config));
    this.middlewareStack.use((0, import_middleware_logger.getLoggerPlugin)(this.config));
    this.middlewareStack.use((0, import_middleware_recursion_detection.getRecursionDetectionPlugin)(this.config));
    this.middlewareStack.use(
      (0, import_core.getHttpAuthSchemeEndpointRuleSetPlugin)(this.config, {
        httpAuthSchemeParametersProvider: import_httpAuthSchemeProvider.defaultSSOHttpAuthSchemeParametersProvider,
        identityProviderConfigProvider: async (config) => new import_core.DefaultIdentityProviderConfig({
          "aws.auth#sigv4": config.credentials
        })
      })
    );
    this.middlewareStack.use((0, import_core.getHttpSigningPlugin)(this.config));
  }
  /**
   * Destroy underlying resources, like sockets. It's usually not necessary to do this.
   * However in Node.js, it's best to explicitly shut down the client's agent when it is no longer needed.
   * Otherwise, sockets might stay open for quite a long time before the server terminates them.
   */
  destroy() {
    super.destroy();
  }
};
__name(_SSOClient, "SSOClient");
var SSOClient = _SSOClient;

// src/SSO.ts


// src/commands/GetRoleCredentialsCommand.ts

var import_middleware_serde = __nccwpck_require__(1238);


// src/models/models_0.ts


// src/models/SSOServiceException.ts

var _SSOServiceException = class _SSOServiceException extends import_smithy_client.ServiceException {
  /**
   * @internal
   */
  constructor(options) {
    super(options);
    Object.setPrototypeOf(this, _SSOServiceException.prototype);
  }
};
__name(_SSOServiceException, "SSOServiceException");
var SSOServiceException = _SSOServiceException;

// src/models/models_0.ts
var _InvalidRequestException = class _InvalidRequestException extends SSOServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "InvalidRequestException",
      $fault: "client",
      ...opts
    });
    this.name = "InvalidRequestException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _InvalidRequestException.prototype);
  }
};
__name(_InvalidRequestException, "InvalidRequestException");
var InvalidRequestException = _InvalidRequestException;
var _ResourceNotFoundException = class _ResourceNotFoundException extends SSOServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "ResourceNotFoundException",
      $fault: "client",
      ...opts
    });
    this.name = "ResourceNotFoundException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _ResourceNotFoundException.prototype);
  }
};
__name(_ResourceNotFoundException, "ResourceNotFoundException");
var ResourceNotFoundException = _ResourceNotFoundException;
var _TooManyRequestsException = class _TooManyRequestsException extends SSOServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "TooManyRequestsException",
      $fault: "client",
      ...opts
    });
    this.name = "TooManyRequestsException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _TooManyRequestsException.prototype);
  }
};
__name(_TooManyRequestsException, "TooManyRequestsException");
var TooManyRequestsException = _TooManyRequestsException;
var _UnauthorizedException = class _UnauthorizedException extends SSOServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "UnauthorizedException",
      $fault: "client",
      ...opts
    });
    this.name = "UnauthorizedException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _UnauthorizedException.prototype);
  }
};
__name(_UnauthorizedException, "UnauthorizedException");
var UnauthorizedException = _UnauthorizedException;
var GetRoleCredentialsRequestFilterSensitiveLog = /* @__PURE__ */ __name((obj) => ({
  ...obj,
  ...obj.accessToken && { accessToken: import_smithy_client.SENSITIVE_STRING }
}), "GetRoleCredentialsRequestFilterSensitiveLog");
var RoleCredentialsFilterSensitiveLog = /* @__PURE__ */ __name((obj) => ({
  ...obj,
  ...obj.secretAccessKey && { secretAccessKey: import_smithy_client.SENSITIVE_STRING },
  ...obj.sessionToken && { sessionToken: import_smithy_client.SENSITIVE_STRING }
}), "RoleCredentialsFilterSensitiveLog");
var GetRoleCredentialsResponseFilterSensitiveLog = /* @__PURE__ */ __name((obj) => ({
  ...obj,
  ...obj.roleCredentials && { roleCredentials: RoleCredentialsFilterSensitiveLog(obj.roleCredentials) }
}), "GetRoleCredentialsResponseFilterSensitiveLog");
var ListAccountRolesRequestFilterSensitiveLog = /* @__PURE__ */ __name((obj) => ({
  ...obj,
  ...obj.accessToken && { accessToken: import_smithy_client.SENSITIVE_STRING }
}), "ListAccountRolesRequestFilterSensitiveLog");
var ListAccountsRequestFilterSensitiveLog = /* @__PURE__ */ __name((obj) => ({
  ...obj,
  ...obj.accessToken && { accessToken: import_smithy_client.SENSITIVE_STRING }
}), "ListAccountsRequestFilterSensitiveLog");
var LogoutRequestFilterSensitiveLog = /* @__PURE__ */ __name((obj) => ({
  ...obj,
  ...obj.accessToken && { accessToken: import_smithy_client.SENSITIVE_STRING }
}), "LogoutRequestFilterSensitiveLog");

// src/protocols/Aws_restJson1.ts
var import_core2 = __nccwpck_require__(9963);


var se_GetRoleCredentialsCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = (0, import_smithy_client.map)({}, isSerializableHeaderValue, {
    [_xasbt]: input[_aT]
  });
  b.bp("/federation/credentials");
  const query = (0, import_smithy_client.map)({
    [_rn]: [, (0, import_smithy_client.expectNonNull)(input[_rN], `roleName`)],
    [_ai]: [, (0, import_smithy_client.expectNonNull)(input[_aI], `accountId`)]
  });
  let body;
  b.m("GET").h(headers).q(query).b(body);
  return b.build();
}, "se_GetRoleCredentialsCommand");
var se_ListAccountRolesCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = (0, import_smithy_client.map)({}, isSerializableHeaderValue, {
    [_xasbt]: input[_aT]
  });
  b.bp("/assignment/roles");
  const query = (0, import_smithy_client.map)({
    [_nt]: [, input[_nT]],
    [_mr]: [() => input.maxResults !== void 0, () => input[_mR].toString()],
    [_ai]: [, (0, import_smithy_client.expectNonNull)(input[_aI], `accountId`)]
  });
  let body;
  b.m("GET").h(headers).q(query).b(body);
  return b.build();
}, "se_ListAccountRolesCommand");
var se_ListAccountsCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = (0, import_smithy_client.map)({}, isSerializableHeaderValue, {
    [_xasbt]: input[_aT]
  });
  b.bp("/assignment/accounts");
  const query = (0, import_smithy_client.map)({
    [_nt]: [, input[_nT]],
    [_mr]: [() => input.maxResults !== void 0, () => input[_mR].toString()]
  });
  let body;
  b.m("GET").h(headers).q(query).b(body);
  return b.build();
}, "se_ListAccountsCommand");
var se_LogoutCommand = /* @__PURE__ */ __name(async (input, context) => {
  const b = (0, import_core.requestBuilder)(input, context);
  const headers = (0, import_smithy_client.map)({}, isSerializableHeaderValue, {
    [_xasbt]: input[_aT]
  });
  b.bp("/logout");
  let body;
  b.m("POST").h(headers).b(body);
  return b.build();
}, "se_LogoutCommand");
var de_GetRoleCredentialsCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    roleCredentials: import_smithy_client._json
  });
  Object.assign(contents, doc);
  return contents;
}, "de_GetRoleCredentialsCommand");
var de_ListAccountRolesCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    nextToken: import_smithy_client.expectString,
    roleList: import_smithy_client._json
  });
  Object.assign(contents, doc);
  return contents;
}, "de_ListAccountRolesCommand");
var de_ListAccountsCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  const data = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.expectObject)(await (0, import_core2.parseJsonBody)(output.body, context)), "body");
  const doc = (0, import_smithy_client.take)(data, {
    accountList: import_smithy_client._json,
    nextToken: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  return contents;
}, "de_ListAccountsCommand");
var de_LogoutCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = (0, import_smithy_client.map)({
    $metadata: deserializeMetadata(output)
  });
  await (0, import_smithy_client.collectBody)(output.body, context);
  return contents;
}, "de_LogoutCommand");
var de_CommandError = /* @__PURE__ */ __name(async (output, context) => {
  const parsedOutput = {
    ...output,
    body: await (0, import_core2.parseJsonErrorBody)(output.body, context)
  };
  const errorCode = (0, import_core2.loadRestJsonErrorCode)(output, parsedOutput.body);
  switch (errorCode) {
    case "InvalidRequestException":
    case "com.amazonaws.sso#InvalidRequestException":
      throw await de_InvalidRequestExceptionRes(parsedOutput, context);
    case "ResourceNotFoundException":
    case "com.amazonaws.sso#ResourceNotFoundException":
      throw await de_ResourceNotFoundExceptionRes(parsedOutput, context);
    case "TooManyRequestsException":
    case "com.amazonaws.sso#TooManyRequestsException":
      throw await de_TooManyRequestsExceptionRes(parsedOutput, context);
    case "UnauthorizedException":
    case "com.amazonaws.sso#UnauthorizedException":
      throw await de_UnauthorizedExceptionRes(parsedOutput, context);
    default:
      const parsedBody = parsedOutput.body;
      return throwDefaultError({
        output,
        parsedBody,
        errorCode
      });
  }
}, "de_CommandError");
var throwDefaultError = (0, import_smithy_client.withBaseException)(SSOServiceException);
var de_InvalidRequestExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const contents = (0, import_smithy_client.map)({});
  const data = parsedOutput.body;
  const doc = (0, import_smithy_client.take)(data, {
    message: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  const exception = new InvalidRequestException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return (0, import_smithy_client.decorateServiceException)(exception, parsedOutput.body);
}, "de_InvalidRequestExceptionRes");
var de_ResourceNotFoundExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const contents = (0, import_smithy_client.map)({});
  const data = parsedOutput.body;
  const doc = (0, import_smithy_client.take)(data, {
    message: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  const exception = new ResourceNotFoundException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return (0, import_smithy_client.decorateServiceException)(exception, parsedOutput.body);
}, "de_ResourceNotFoundExceptionRes");
var de_TooManyRequestsExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const contents = (0, import_smithy_client.map)({});
  const data = parsedOutput.body;
  const doc = (0, import_smithy_client.take)(data, {
    message: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  const exception = new TooManyRequestsException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return (0, import_smithy_client.decorateServiceException)(exception, parsedOutput.body);
}, "de_TooManyRequestsExceptionRes");
var de_UnauthorizedExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const contents = (0, import_smithy_client.map)({});
  const data = parsedOutput.body;
  const doc = (0, import_smithy_client.take)(data, {
    message: import_smithy_client.expectString
  });
  Object.assign(contents, doc);
  const exception = new UnauthorizedException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return (0, import_smithy_client.decorateServiceException)(exception, parsedOutput.body);
}, "de_UnauthorizedExceptionRes");
var deserializeMetadata = /* @__PURE__ */ __name((output) => ({
  httpStatusCode: output.statusCode,
  requestId: output.headers["x-amzn-requestid"] ?? output.headers["x-amzn-request-id"] ?? output.headers["x-amz-request-id"],
  extendedRequestId: output.headers["x-amz-id-2"],
  cfId: output.headers["x-amz-cf-id"]
}), "deserializeMetadata");
var isSerializableHeaderValue = /* @__PURE__ */ __name((value) => value !== void 0 && value !== null && value !== "" && (!Object.getOwnPropertyNames(value).includes("length") || value.length != 0) && (!Object.getOwnPropertyNames(value).includes("size") || value.size != 0), "isSerializableHeaderValue");
var _aI = "accountId";
var _aT = "accessToken";
var _ai = "account_id";
var _mR = "maxResults";
var _mr = "max_result";
var _nT = "nextToken";
var _nt = "next_token";
var _rN = "roleName";
var _rn = "role_name";
var _xasbt = "x-amz-sso_bearer_token";

// src/commands/GetRoleCredentialsCommand.ts
var _GetRoleCredentialsCommand = class _GetRoleCredentialsCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SWBPortalService", "GetRoleCredentials", {}).n("SSOClient", "GetRoleCredentialsCommand").f(GetRoleCredentialsRequestFilterSensitiveLog, GetRoleCredentialsResponseFilterSensitiveLog).ser(se_GetRoleCredentialsCommand).de(de_GetRoleCredentialsCommand).build() {
};
__name(_GetRoleCredentialsCommand, "GetRoleCredentialsCommand");
var GetRoleCredentialsCommand = _GetRoleCredentialsCommand;

// src/commands/ListAccountRolesCommand.ts



var _ListAccountRolesCommand = class _ListAccountRolesCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SWBPortalService", "ListAccountRoles", {}).n("SSOClient", "ListAccountRolesCommand").f(ListAccountRolesRequestFilterSensitiveLog, void 0).ser(se_ListAccountRolesCommand).de(de_ListAccountRolesCommand).build() {
};
__name(_ListAccountRolesCommand, "ListAccountRolesCommand");
var ListAccountRolesCommand = _ListAccountRolesCommand;

// src/commands/ListAccountsCommand.ts



var _ListAccountsCommand = class _ListAccountsCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SWBPortalService", "ListAccounts", {}).n("SSOClient", "ListAccountsCommand").f(ListAccountsRequestFilterSensitiveLog, void 0).ser(se_ListAccountsCommand).de(de_ListAccountsCommand).build() {
};
__name(_ListAccountsCommand, "ListAccountsCommand");
var ListAccountsCommand = _ListAccountsCommand;

// src/commands/LogoutCommand.ts



var _LogoutCommand = class _LogoutCommand extends import_smithy_client.Command.classBuilder().ep({
  ...commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("SWBPortalService", "Logout", {}).n("SSOClient", "LogoutCommand").f(LogoutRequestFilterSensitiveLog, void 0).ser(se_LogoutCommand).de(de_LogoutCommand).build() {
};
__name(_LogoutCommand, "LogoutCommand");
var LogoutCommand = _LogoutCommand;

// src/SSO.ts
var commands = {
  GetRoleCredentialsCommand,
  ListAccountRolesCommand,
  ListAccountsCommand,
  LogoutCommand
};
var _SSO = class _SSO extends SSOClient {
};
__name(_SSO, "SSO");
var SSO = _SSO;
(0, import_smithy_client.createAggregatedClient)(commands, SSO);

// src/pagination/ListAccountRolesPaginator.ts

var paginateListAccountRoles = (0, import_core.createPaginator)(SSOClient, ListAccountRolesCommand, "nextToken", "nextToken", "maxResults");

// src/pagination/ListAccountsPaginator.ts

var paginateListAccounts = (0, import_core.createPaginator)(SSOClient, ListAccountsCommand, "nextToken", "nextToken", "maxResults");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 9756:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.getRuntimeConfig = void 0;
const tslib_1 = __nccwpck_require__(4351);
const package_json_1 = tslib_1.__importDefault(__nccwpck_require__(1092));
const core_1 = __nccwpck_require__(9963);
const util_user_agent_node_1 = __nccwpck_require__(8095);
const config_resolver_1 = __nccwpck_require__(3098);
const hash_node_1 = __nccwpck_require__(3081);
const middleware_retry_1 = __nccwpck_require__(6039);
const node_config_provider_1 = __nccwpck_require__(3461);
const node_http_handler_1 = __nccwpck_require__(258);
const util_body_length_node_1 = __nccwpck_require__(8075);
const util_retry_1 = __nccwpck_require__(4902);
const runtimeConfig_shared_1 = __nccwpck_require__(4809);
const smithy_client_1 = __nccwpck_require__(3570);
const util_defaults_mode_node_1 = __nccwpck_require__(2429);
const smithy_client_2 = __nccwpck_require__(3570);
const getRuntimeConfig = (config) => {
    (0, smithy_client_2.emitWarningIfUnsupportedVersion)(process.version);
    const defaultsMode = (0, util_defaults_mode_node_1.resolveDefaultsModeConfig)(config);
    const defaultConfigProvider = () => defaultsMode().then(smithy_client_1.loadConfigsForDefaultMode);
    const clientSharedValues = (0, runtimeConfig_shared_1.getRuntimeConfig)(config);
    (0, core_1.emitWarningIfUnsupportedVersion)(process.version);
    return {
        ...clientSharedValues,
        ...config,
        runtime: "node",
        defaultsMode,
        bodyLengthChecker: config?.bodyLengthChecker ?? util_body_length_node_1.calculateBodyLength,
        defaultUserAgentProvider: config?.defaultUserAgentProvider ??
            (0, util_user_agent_node_1.defaultUserAgent)({ serviceId: clientSharedValues.serviceId, clientVersion: package_json_1.default.version }),
        maxAttempts: config?.maxAttempts ?? (0, node_config_provider_1.loadConfig)(middleware_retry_1.NODE_MAX_ATTEMPT_CONFIG_OPTIONS),
        region: config?.region ?? (0, node_config_provider_1.loadConfig)(config_resolver_1.NODE_REGION_CONFIG_OPTIONS, config_resolver_1.NODE_REGION_CONFIG_FILE_OPTIONS),
        requestHandler: node_http_handler_1.NodeHttpHandler.create(config?.requestHandler ?? defaultConfigProvider),
        retryMode: config?.retryMode ??
            (0, node_config_provider_1.loadConfig)({
                ...middleware_retry_1.NODE_RETRY_MODE_CONFIG_OPTIONS,
                default: async () => (await defaultConfigProvider()).retryMode || util_retry_1.DEFAULT_RETRY_MODE,
            }),
        sha256: config?.sha256 ?? hash_node_1.Hash.bind(null, "sha256"),
        streamCollector: config?.streamCollector ?? node_http_handler_1.streamCollector,
        useDualstackEndpoint: config?.useDualstackEndpoint ?? (0, node_config_provider_1.loadConfig)(config_resolver_1.NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS),
        useFipsEndpoint: config?.useFipsEndpoint ?? (0, node_config_provider_1.loadConfig)(config_resolver_1.NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS),
    };
};
exports.getRuntimeConfig = getRuntimeConfig;


/***/ }),

/***/ 4809:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.getRuntimeConfig = void 0;
const core_1 = __nccwpck_require__(9963);
const core_2 = __nccwpck_require__(5829);
const smithy_client_1 = __nccwpck_require__(3570);
const url_parser_1 = __nccwpck_require__(4681);
const util_base64_1 = __nccwpck_require__(5600);
const util_utf8_1 = __nccwpck_require__(1895);
const httpAuthSchemeProvider_1 = __nccwpck_require__(9344);
const endpointResolver_1 = __nccwpck_require__(898);
const getRuntimeConfig = (config) => {
    return {
        apiVersion: "2019-06-10",
        base64Decoder: config?.base64Decoder ?? util_base64_1.fromBase64,
        base64Encoder: config?.base64Encoder ?? util_base64_1.toBase64,
        disableHostPrefix: config?.disableHostPrefix ?? false,
        endpointProvider: config?.endpointProvider ?? endpointResolver_1.defaultEndpointResolver,
        extensions: config?.extensions ?? [],
        httpAuthSchemeProvider: config?.httpAuthSchemeProvider ?? httpAuthSchemeProvider_1.defaultSSOHttpAuthSchemeProvider,
        httpAuthSchemes: config?.httpAuthSchemes ?? [
            {
                schemeId: "aws.auth#sigv4",
                identityProvider: (ipc) => ipc.getIdentityProvider("aws.auth#sigv4"),
                signer: new core_1.AwsSdkSigV4Signer(),
            },
            {
                schemeId: "smithy.api#noAuth",
                identityProvider: (ipc) => ipc.getIdentityProvider("smithy.api#noAuth") || (async () => ({})),
                signer: new core_2.NoAuthSigner(),
            },
        ],
        logger: config?.logger ?? new smithy_client_1.NoOpLogger(),
        serviceId: config?.serviceId ?? "SSO",
        urlParser: config?.urlParser ?? url_parser_1.parseUrl,
        utf8Decoder: config?.utf8Decoder ?? util_utf8_1.fromUtf8,
        utf8Encoder: config?.utf8Encoder ?? util_utf8_1.toUtf8,
    };
};
exports.getRuntimeConfig = getRuntimeConfig;


/***/ }),

/***/ 4195:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.STSClient = exports.__Client = void 0;
const middleware_host_header_1 = __nccwpck_require__(2545);
const middleware_logger_1 = __nccwpck_require__(14);
const middleware_recursion_detection_1 = __nccwpck_require__(5525);
const middleware_user_agent_1 = __nccwpck_require__(4688);
const config_resolver_1 = __nccwpck_require__(3098);
const core_1 = __nccwpck_require__(5829);
const middleware_content_length_1 = __nccwpck_require__(2800);
const middleware_endpoint_1 = __nccwpck_require__(2918);
const middleware_retry_1 = __nccwpck_require__(6039);
const smithy_client_1 = __nccwpck_require__(3570);
Object.defineProperty(exports, "__Client", ({ enumerable: true, get: function () { return smithy_client_1.Client; } }));
const httpAuthSchemeProvider_1 = __nccwpck_require__(7145);
const EndpointParameters_1 = __nccwpck_require__(510);
const runtimeConfig_1 = __nccwpck_require__(3405);
const runtimeExtensions_1 = __nccwpck_require__(2053);
class STSClient extends smithy_client_1.Client {
    constructor(...[configuration]) {
        const _config_0 = (0, runtimeConfig_1.getRuntimeConfig)(configuration || {});
        const _config_1 = (0, EndpointParameters_1.resolveClientEndpointParameters)(_config_0);
        const _config_2 = (0, middleware_user_agent_1.resolveUserAgentConfig)(_config_1);
        const _config_3 = (0, middleware_retry_1.resolveRetryConfig)(_config_2);
        const _config_4 = (0, config_resolver_1.resolveRegionConfig)(_config_3);
        const _config_5 = (0, middleware_host_header_1.resolveHostHeaderConfig)(_config_4);
        const _config_6 = (0, middleware_endpoint_1.resolveEndpointConfig)(_config_5);
        const _config_7 = (0, httpAuthSchemeProvider_1.resolveHttpAuthSchemeConfig)(_config_6);
        const _config_8 = (0, runtimeExtensions_1.resolveRuntimeExtensions)(_config_7, configuration?.extensions || []);
        super(_config_8);
        this.config = _config_8;
        this.middlewareStack.use((0, middleware_user_agent_1.getUserAgentPlugin)(this.config));
        this.middlewareStack.use((0, middleware_retry_1.getRetryPlugin)(this.config));
        this.middlewareStack.use((0, middleware_content_length_1.getContentLengthPlugin)(this.config));
        this.middlewareStack.use((0, middleware_host_header_1.getHostHeaderPlugin)(this.config));
        this.middlewareStack.use((0, middleware_logger_1.getLoggerPlugin)(this.config));
        this.middlewareStack.use((0, middleware_recursion_detection_1.getRecursionDetectionPlugin)(this.config));
        this.middlewareStack.use((0, core_1.getHttpAuthSchemeEndpointRuleSetPlugin)(this.config, {
            httpAuthSchemeParametersProvider: httpAuthSchemeProvider_1.defaultSTSHttpAuthSchemeParametersProvider,
            identityProviderConfigProvider: async (config) => new core_1.DefaultIdentityProviderConfig({
                "aws.auth#sigv4": config.credentials,
            }),
        }));
        this.middlewareStack.use((0, core_1.getHttpSigningPlugin)(this.config));
    }
    destroy() {
        super.destroy();
    }
}
exports.STSClient = STSClient;


/***/ }),

/***/ 8527:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.resolveHttpAuthRuntimeConfig = exports.getHttpAuthExtensionConfiguration = void 0;
const getHttpAuthExtensionConfiguration = (runtimeConfig) => {
    const _httpAuthSchemes = runtimeConfig.httpAuthSchemes;
    let _httpAuthSchemeProvider = runtimeConfig.httpAuthSchemeProvider;
    let _credentials = runtimeConfig.credentials;
    return {
        setHttpAuthScheme(httpAuthScheme) {
            const index = _httpAuthSchemes.findIndex((scheme) => scheme.schemeId === httpAuthScheme.schemeId);
            if (index === -1) {
                _httpAuthSchemes.push(httpAuthScheme);
            }
            else {
                _httpAuthSchemes.splice(index, 1, httpAuthScheme);
            }
        },
        httpAuthSchemes() {
            return _httpAuthSchemes;
        },
        setHttpAuthSchemeProvider(httpAuthSchemeProvider) {
            _httpAuthSchemeProvider = httpAuthSchemeProvider;
        },
        httpAuthSchemeProvider() {
            return _httpAuthSchemeProvider;
        },
        setCredentials(credentials) {
            _credentials = credentials;
        },
        credentials() {
            return _credentials;
        },
    };
};
exports.getHttpAuthExtensionConfiguration = getHttpAuthExtensionConfiguration;
const resolveHttpAuthRuntimeConfig = (config) => {
    return {
        httpAuthSchemes: config.httpAuthSchemes(),
        httpAuthSchemeProvider: config.httpAuthSchemeProvider(),
        credentials: config.credentials(),
    };
};
exports.resolveHttpAuthRuntimeConfig = resolveHttpAuthRuntimeConfig;


/***/ }),

/***/ 7145:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.resolveHttpAuthSchemeConfig = exports.resolveStsAuthConfig = exports.defaultSTSHttpAuthSchemeProvider = exports.defaultSTSHttpAuthSchemeParametersProvider = void 0;
const core_1 = __nccwpck_require__(9963);
const util_middleware_1 = __nccwpck_require__(2390);
const STSClient_1 = __nccwpck_require__(4195);
const defaultSTSHttpAuthSchemeParametersProvider = async (config, context, input) => {
    return {
        operation: (0, util_middleware_1.getSmithyContext)(context).operation,
        region: (await (0, util_middleware_1.normalizeProvider)(config.region)()) ||
            (() => {
                throw new Error("expected `region` to be configured for `aws.auth#sigv4`");
            })(),
    };
};
exports.defaultSTSHttpAuthSchemeParametersProvider = defaultSTSHttpAuthSchemeParametersProvider;
function createAwsAuthSigv4HttpAuthOption(authParameters) {
    return {
        schemeId: "aws.auth#sigv4",
        signingProperties: {
            name: "sts",
            region: authParameters.region,
        },
        propertiesExtractor: (config, context) => ({
            signingProperties: {
                config,
                context,
            },
        }),
    };
}
function createSmithyApiNoAuthHttpAuthOption(authParameters) {
    return {
        schemeId: "smithy.api#noAuth",
    };
}
const defaultSTSHttpAuthSchemeProvider = (authParameters) => {
    const options = [];
    switch (authParameters.operation) {
        case "AssumeRoleWithSAML": {
            options.push(createSmithyApiNoAuthHttpAuthOption(authParameters));
            break;
        }
        case "AssumeRoleWithWebIdentity": {
            options.push(createSmithyApiNoAuthHttpAuthOption(authParameters));
            break;
        }
        default: {
            options.push(createAwsAuthSigv4HttpAuthOption(authParameters));
        }
    }
    return options;
};
exports.defaultSTSHttpAuthSchemeProvider = defaultSTSHttpAuthSchemeProvider;
const resolveStsAuthConfig = (input) => ({
    ...input,
    stsClientCtor: STSClient_1.STSClient,
});
exports.resolveStsAuthConfig = resolveStsAuthConfig;
const resolveHttpAuthSchemeConfig = (config) => {
    const config_0 = (0, exports.resolveStsAuthConfig)(config);
    const config_1 = (0, core_1.resolveAwsSdkSigV4Config)(config_0);
    return {
        ...config_1,
    };
};
exports.resolveHttpAuthSchemeConfig = resolveHttpAuthSchemeConfig;


/***/ }),

/***/ 510:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.commonParams = exports.resolveClientEndpointParameters = void 0;
const resolveClientEndpointParameters = (options) => {
    return {
        ...options,
        useDualstackEndpoint: options.useDualstackEndpoint ?? false,
        useFipsEndpoint: options.useFipsEndpoint ?? false,
        useGlobalEndpoint: options.useGlobalEndpoint ?? false,
        defaultSigningName: "sts",
    };
};
exports.resolveClientEndpointParameters = resolveClientEndpointParameters;
exports.commonParams = {
    UseGlobalEndpoint: { type: "builtInParams", name: "useGlobalEndpoint" },
    UseFIPS: { type: "builtInParams", name: "useFipsEndpoint" },
    Endpoint: { type: "builtInParams", name: "endpoint" },
    Region: { type: "builtInParams", name: "region" },
    UseDualStack: { type: "builtInParams", name: "useDualstackEndpoint" },
};


/***/ }),

/***/ 1203:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.defaultEndpointResolver = void 0;
const util_endpoints_1 = __nccwpck_require__(3350);
const util_endpoints_2 = __nccwpck_require__(5473);
const ruleset_1 = __nccwpck_require__(6882);
const defaultEndpointResolver = (endpointParams, context = {}) => {
    return (0, util_endpoints_2.resolveEndpoint)(ruleset_1.ruleSet, {
        endpointParams: endpointParams,
        logger: context.logger,
    });
};
exports.defaultEndpointResolver = defaultEndpointResolver;
util_endpoints_2.customEndpointFunctions.aws = util_endpoints_1.awsEndpointFunctions;


/***/ }),

/***/ 6882:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ruleSet = void 0;
const F = "required", G = "type", H = "fn", I = "argv", J = "ref";
const a = false, b = true, c = "booleanEquals", d = "stringEquals", e = "sigv4", f = "sts", g = "us-east-1", h = "endpoint", i = "https://sts.{Region}.{PartitionResult#dnsSuffix}", j = "tree", k = "error", l = "getAttr", m = { [F]: false, [G]: "String" }, n = { [F]: true, "default": false, [G]: "Boolean" }, o = { [J]: "Endpoint" }, p = { [H]: "isSet", [I]: [{ [J]: "Region" }] }, q = { [J]: "Region" }, r = { [H]: "aws.partition", [I]: [q], "assign": "PartitionResult" }, s = { [J]: "UseFIPS" }, t = { [J]: "UseDualStack" }, u = { "url": "https://sts.amazonaws.com", "properties": { "authSchemes": [{ "name": e, "signingName": f, "signingRegion": g }] }, "headers": {} }, v = {}, w = { "conditions": [{ [H]: d, [I]: [q, "aws-global"] }], [h]: u, [G]: h }, x = { [H]: c, [I]: [s, true] }, y = { [H]: c, [I]: [t, true] }, z = { [H]: l, [I]: [{ [J]: "PartitionResult" }, "supportsFIPS"] }, A = { [J]: "PartitionResult" }, B = { [H]: c, [I]: [true, { [H]: l, [I]: [A, "supportsDualStack"] }] }, C = [{ [H]: "isSet", [I]: [o] }], D = [x], E = [y];
const _data = { version: "1.0", parameters: { Region: m, UseDualStack: n, UseFIPS: n, Endpoint: m, UseGlobalEndpoint: n }, rules: [{ conditions: [{ [H]: c, [I]: [{ [J]: "UseGlobalEndpoint" }, b] }, { [H]: "not", [I]: C }, p, r, { [H]: c, [I]: [s, a] }, { [H]: c, [I]: [t, a] }], rules: [{ conditions: [{ [H]: d, [I]: [q, "ap-northeast-1"] }], endpoint: u, [G]: h }, { conditions: [{ [H]: d, [I]: [q, "ap-south-1"] }], endpoint: u, [G]: h }, { conditions: [{ [H]: d, [I]: [q, "ap-southeast-1"] }], endpoint: u, [G]: h }, { conditions: [{ [H]: d, [I]: [q, "ap-southeast-2"] }], endpoint: u, [G]: h }, w, { conditions: [{ [H]: d, [I]: [q, "ca-central-1"] }], endpoint: u, [G]: h }, { conditions: [{ [H]: d, [I]: [q, "eu-central-1"] }], endpoint: u, [G]: h }, { conditions: [{ [H]: d, [I]: [q, "eu-north-1"] }], endpoint: u, [G]: h }, { conditions: [{ [H]: d, [I]: [q, "eu-west-1"] }], endpoint: u, [G]: h }, { conditions: [{ [H]: d, [I]: [q, "eu-west-2"] }], endpoint: u, [G]: h }, { conditions: [{ [H]: d, [I]: [q, "eu-west-3"] }], endpoint: u, [G]: h }, { conditions: [{ [H]: d, [I]: [q, "sa-east-1"] }], endpoint: u, [G]: h }, { conditions: [{ [H]: d, [I]: [q, g] }], endpoint: u, [G]: h }, { conditions: [{ [H]: d, [I]: [q, "us-east-2"] }], endpoint: u, [G]: h }, { conditions: [{ [H]: d, [I]: [q, "us-west-1"] }], endpoint: u, [G]: h }, { conditions: [{ [H]: d, [I]: [q, "us-west-2"] }], endpoint: u, [G]: h }, { endpoint: { url: i, properties: { authSchemes: [{ name: e, signingName: f, signingRegion: "{Region}" }] }, headers: v }, [G]: h }], [G]: j }, { conditions: C, rules: [{ conditions: D, error: "Invalid Configuration: FIPS and custom endpoint are not supported", [G]: k }, { conditions: E, error: "Invalid Configuration: Dualstack and custom endpoint are not supported", [G]: k }, { endpoint: { url: o, properties: v, headers: v }, [G]: h }], [G]: j }, { conditions: [p], rules: [{ conditions: [r], rules: [{ conditions: [x, y], rules: [{ conditions: [{ [H]: c, [I]: [b, z] }, B], rules: [{ endpoint: { url: "https://sts-fips.{Region}.{PartitionResult#dualStackDnsSuffix}", properties: v, headers: v }, [G]: h }], [G]: j }, { error: "FIPS and DualStack are enabled, but this partition does not support one or both", [G]: k }], [G]: j }, { conditions: D, rules: [{ conditions: [{ [H]: c, [I]: [z, b] }], rules: [{ conditions: [{ [H]: d, [I]: [{ [H]: l, [I]: [A, "name"] }, "aws-us-gov"] }], endpoint: { url: "https://sts.{Region}.amazonaws.com", properties: v, headers: v }, [G]: h }, { endpoint: { url: "https://sts-fips.{Region}.{PartitionResult#dnsSuffix}", properties: v, headers: v }, [G]: h }], [G]: j }, { error: "FIPS is enabled but this partition does not support FIPS", [G]: k }], [G]: j }, { conditions: E, rules: [{ conditions: [B], rules: [{ endpoint: { url: "https://sts.{Region}.{PartitionResult#dualStackDnsSuffix}", properties: v, headers: v }, [G]: h }], [G]: j }, { error: "DualStack is enabled but this partition does not support DualStack", [G]: k }], [G]: j }, w, { endpoint: { url: i, properties: v, headers: v }, [G]: h }], [G]: j }], [G]: j }, { error: "Invalid Configuration: Missing Region", [G]: k }] };
exports.ruleSet = _data;


/***/ }),

/***/ 2209:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __reExport = (target, mod, secondTarget) => (__copyProps(target, mod, "default"), secondTarget && __copyProps(secondTarget, mod, "default"));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  AssumeRoleCommand: () => AssumeRoleCommand,
  AssumeRoleResponseFilterSensitiveLog: () => AssumeRoleResponseFilterSensitiveLog,
  AssumeRoleWithSAMLCommand: () => AssumeRoleWithSAMLCommand,
  AssumeRoleWithSAMLRequestFilterSensitiveLog: () => AssumeRoleWithSAMLRequestFilterSensitiveLog,
  AssumeRoleWithSAMLResponseFilterSensitiveLog: () => AssumeRoleWithSAMLResponseFilterSensitiveLog,
  AssumeRoleWithWebIdentityCommand: () => AssumeRoleWithWebIdentityCommand,
  AssumeRoleWithWebIdentityRequestFilterSensitiveLog: () => AssumeRoleWithWebIdentityRequestFilterSensitiveLog,
  AssumeRoleWithWebIdentityResponseFilterSensitiveLog: () => AssumeRoleWithWebIdentityResponseFilterSensitiveLog,
  ClientInputEndpointParameters: () => import_EndpointParameters9.ClientInputEndpointParameters,
  CredentialsFilterSensitiveLog: () => CredentialsFilterSensitiveLog,
  DecodeAuthorizationMessageCommand: () => DecodeAuthorizationMessageCommand,
  ExpiredTokenException: () => ExpiredTokenException,
  GetAccessKeyInfoCommand: () => GetAccessKeyInfoCommand,
  GetCallerIdentityCommand: () => GetCallerIdentityCommand,
  GetFederationTokenCommand: () => GetFederationTokenCommand,
  GetFederationTokenResponseFilterSensitiveLog: () => GetFederationTokenResponseFilterSensitiveLog,
  GetSessionTokenCommand: () => GetSessionTokenCommand,
  GetSessionTokenResponseFilterSensitiveLog: () => GetSessionTokenResponseFilterSensitiveLog,
  IDPCommunicationErrorException: () => IDPCommunicationErrorException,
  IDPRejectedClaimException: () => IDPRejectedClaimException,
  InvalidAuthorizationMessageException: () => InvalidAuthorizationMessageException,
  InvalidIdentityTokenException: () => InvalidIdentityTokenException,
  MalformedPolicyDocumentException: () => MalformedPolicyDocumentException,
  PackedPolicyTooLargeException: () => PackedPolicyTooLargeException,
  RegionDisabledException: () => RegionDisabledException,
  STS: () => STS,
  STSServiceException: () => STSServiceException,
  decorateDefaultCredentialProvider: () => decorateDefaultCredentialProvider,
  getDefaultRoleAssumer: () => getDefaultRoleAssumer2,
  getDefaultRoleAssumerWithWebIdentity: () => getDefaultRoleAssumerWithWebIdentity2
});
module.exports = __toCommonJS(src_exports);
__reExport(src_exports, __nccwpck_require__(4195), module.exports);

// src/STS.ts


// src/commands/AssumeRoleCommand.ts
var import_middleware_endpoint = __nccwpck_require__(2918);
var import_middleware_serde = __nccwpck_require__(1238);

var import_EndpointParameters = __nccwpck_require__(510);

// src/models/models_0.ts


// src/models/STSServiceException.ts
var import_smithy_client = __nccwpck_require__(3570);
var _STSServiceException = class _STSServiceException extends import_smithy_client.ServiceException {
  /**
   * @internal
   */
  constructor(options) {
    super(options);
    Object.setPrototypeOf(this, _STSServiceException.prototype);
  }
};
__name(_STSServiceException, "STSServiceException");
var STSServiceException = _STSServiceException;

// src/models/models_0.ts
var _ExpiredTokenException = class _ExpiredTokenException extends STSServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "ExpiredTokenException",
      $fault: "client",
      ...opts
    });
    this.name = "ExpiredTokenException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _ExpiredTokenException.prototype);
  }
};
__name(_ExpiredTokenException, "ExpiredTokenException");
var ExpiredTokenException = _ExpiredTokenException;
var _MalformedPolicyDocumentException = class _MalformedPolicyDocumentException extends STSServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "MalformedPolicyDocumentException",
      $fault: "client",
      ...opts
    });
    this.name = "MalformedPolicyDocumentException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _MalformedPolicyDocumentException.prototype);
  }
};
__name(_MalformedPolicyDocumentException, "MalformedPolicyDocumentException");
var MalformedPolicyDocumentException = _MalformedPolicyDocumentException;
var _PackedPolicyTooLargeException = class _PackedPolicyTooLargeException extends STSServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "PackedPolicyTooLargeException",
      $fault: "client",
      ...opts
    });
    this.name = "PackedPolicyTooLargeException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _PackedPolicyTooLargeException.prototype);
  }
};
__name(_PackedPolicyTooLargeException, "PackedPolicyTooLargeException");
var PackedPolicyTooLargeException = _PackedPolicyTooLargeException;
var _RegionDisabledException = class _RegionDisabledException extends STSServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "RegionDisabledException",
      $fault: "client",
      ...opts
    });
    this.name = "RegionDisabledException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _RegionDisabledException.prototype);
  }
};
__name(_RegionDisabledException, "RegionDisabledException");
var RegionDisabledException = _RegionDisabledException;
var _IDPRejectedClaimException = class _IDPRejectedClaimException extends STSServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "IDPRejectedClaimException",
      $fault: "client",
      ...opts
    });
    this.name = "IDPRejectedClaimException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _IDPRejectedClaimException.prototype);
  }
};
__name(_IDPRejectedClaimException, "IDPRejectedClaimException");
var IDPRejectedClaimException = _IDPRejectedClaimException;
var _InvalidIdentityTokenException = class _InvalidIdentityTokenException extends STSServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "InvalidIdentityTokenException",
      $fault: "client",
      ...opts
    });
    this.name = "InvalidIdentityTokenException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _InvalidIdentityTokenException.prototype);
  }
};
__name(_InvalidIdentityTokenException, "InvalidIdentityTokenException");
var InvalidIdentityTokenException = _InvalidIdentityTokenException;
var _IDPCommunicationErrorException = class _IDPCommunicationErrorException extends STSServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "IDPCommunicationErrorException",
      $fault: "client",
      ...opts
    });
    this.name = "IDPCommunicationErrorException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _IDPCommunicationErrorException.prototype);
  }
};
__name(_IDPCommunicationErrorException, "IDPCommunicationErrorException");
var IDPCommunicationErrorException = _IDPCommunicationErrorException;
var _InvalidAuthorizationMessageException = class _InvalidAuthorizationMessageException extends STSServiceException {
  /**
   * @internal
   */
  constructor(opts) {
    super({
      name: "InvalidAuthorizationMessageException",
      $fault: "client",
      ...opts
    });
    this.name = "InvalidAuthorizationMessageException";
    this.$fault = "client";
    Object.setPrototypeOf(this, _InvalidAuthorizationMessageException.prototype);
  }
};
__name(_InvalidAuthorizationMessageException, "InvalidAuthorizationMessageException");
var InvalidAuthorizationMessageException = _InvalidAuthorizationMessageException;
var CredentialsFilterSensitiveLog = /* @__PURE__ */ __name((obj) => ({
  ...obj,
  ...obj.SecretAccessKey && { SecretAccessKey: import_smithy_client.SENSITIVE_STRING }
}), "CredentialsFilterSensitiveLog");
var AssumeRoleResponseFilterSensitiveLog = /* @__PURE__ */ __name((obj) => ({
  ...obj,
  ...obj.Credentials && { Credentials: CredentialsFilterSensitiveLog(obj.Credentials) }
}), "AssumeRoleResponseFilterSensitiveLog");
var AssumeRoleWithSAMLRequestFilterSensitiveLog = /* @__PURE__ */ __name((obj) => ({
  ...obj,
  ...obj.SAMLAssertion && { SAMLAssertion: import_smithy_client.SENSITIVE_STRING }
}), "AssumeRoleWithSAMLRequestFilterSensitiveLog");
var AssumeRoleWithSAMLResponseFilterSensitiveLog = /* @__PURE__ */ __name((obj) => ({
  ...obj,
  ...obj.Credentials && { Credentials: CredentialsFilterSensitiveLog(obj.Credentials) }
}), "AssumeRoleWithSAMLResponseFilterSensitiveLog");
var AssumeRoleWithWebIdentityRequestFilterSensitiveLog = /* @__PURE__ */ __name((obj) => ({
  ...obj,
  ...obj.WebIdentityToken && { WebIdentityToken: import_smithy_client.SENSITIVE_STRING }
}), "AssumeRoleWithWebIdentityRequestFilterSensitiveLog");
var AssumeRoleWithWebIdentityResponseFilterSensitiveLog = /* @__PURE__ */ __name((obj) => ({
  ...obj,
  ...obj.Credentials && { Credentials: CredentialsFilterSensitiveLog(obj.Credentials) }
}), "AssumeRoleWithWebIdentityResponseFilterSensitiveLog");
var GetFederationTokenResponseFilterSensitiveLog = /* @__PURE__ */ __name((obj) => ({
  ...obj,
  ...obj.Credentials && { Credentials: CredentialsFilterSensitiveLog(obj.Credentials) }
}), "GetFederationTokenResponseFilterSensitiveLog");
var GetSessionTokenResponseFilterSensitiveLog = /* @__PURE__ */ __name((obj) => ({
  ...obj,
  ...obj.Credentials && { Credentials: CredentialsFilterSensitiveLog(obj.Credentials) }
}), "GetSessionTokenResponseFilterSensitiveLog");

// src/protocols/Aws_query.ts
var import_core = __nccwpck_require__(9963);
var import_protocol_http = __nccwpck_require__(4418);

var se_AssumeRoleCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = SHARED_HEADERS;
  let body;
  body = buildFormUrlencodedString({
    ...se_AssumeRoleRequest(input, context),
    [_A]: _AR,
    [_V]: _
  });
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_AssumeRoleCommand");
var se_AssumeRoleWithSAMLCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = SHARED_HEADERS;
  let body;
  body = buildFormUrlencodedString({
    ...se_AssumeRoleWithSAMLRequest(input, context),
    [_A]: _ARWSAML,
    [_V]: _
  });
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_AssumeRoleWithSAMLCommand");
var se_AssumeRoleWithWebIdentityCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = SHARED_HEADERS;
  let body;
  body = buildFormUrlencodedString({
    ...se_AssumeRoleWithWebIdentityRequest(input, context),
    [_A]: _ARWWI,
    [_V]: _
  });
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_AssumeRoleWithWebIdentityCommand");
var se_DecodeAuthorizationMessageCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = SHARED_HEADERS;
  let body;
  body = buildFormUrlencodedString({
    ...se_DecodeAuthorizationMessageRequest(input, context),
    [_A]: _DAM,
    [_V]: _
  });
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_DecodeAuthorizationMessageCommand");
var se_GetAccessKeyInfoCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = SHARED_HEADERS;
  let body;
  body = buildFormUrlencodedString({
    ...se_GetAccessKeyInfoRequest(input, context),
    [_A]: _GAKI,
    [_V]: _
  });
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_GetAccessKeyInfoCommand");
var se_GetCallerIdentityCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = SHARED_HEADERS;
  let body;
  body = buildFormUrlencodedString({
    ...se_GetCallerIdentityRequest(input, context),
    [_A]: _GCI,
    [_V]: _
  });
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_GetCallerIdentityCommand");
var se_GetFederationTokenCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = SHARED_HEADERS;
  let body;
  body = buildFormUrlencodedString({
    ...se_GetFederationTokenRequest(input, context),
    [_A]: _GFT,
    [_V]: _
  });
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_GetFederationTokenCommand");
var se_GetSessionTokenCommand = /* @__PURE__ */ __name(async (input, context) => {
  const headers = SHARED_HEADERS;
  let body;
  body = buildFormUrlencodedString({
    ...se_GetSessionTokenRequest(input, context),
    [_A]: _GST,
    [_V]: _
  });
  return buildHttpRpcRequest(context, headers, "/", void 0, body);
}, "se_GetSessionTokenCommand");
var de_AssumeRoleCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core.parseXmlBody)(output.body, context);
  let contents = {};
  contents = de_AssumeRoleResponse(data.AssumeRoleResult, context);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_AssumeRoleCommand");
var de_AssumeRoleWithSAMLCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core.parseXmlBody)(output.body, context);
  let contents = {};
  contents = de_AssumeRoleWithSAMLResponse(data.AssumeRoleWithSAMLResult, context);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_AssumeRoleWithSAMLCommand");
var de_AssumeRoleWithWebIdentityCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core.parseXmlBody)(output.body, context);
  let contents = {};
  contents = de_AssumeRoleWithWebIdentityResponse(data.AssumeRoleWithWebIdentityResult, context);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_AssumeRoleWithWebIdentityCommand");
var de_DecodeAuthorizationMessageCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core.parseXmlBody)(output.body, context);
  let contents = {};
  contents = de_DecodeAuthorizationMessageResponse(data.DecodeAuthorizationMessageResult, context);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_DecodeAuthorizationMessageCommand");
var de_GetAccessKeyInfoCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core.parseXmlBody)(output.body, context);
  let contents = {};
  contents = de_GetAccessKeyInfoResponse(data.GetAccessKeyInfoResult, context);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_GetAccessKeyInfoCommand");
var de_GetCallerIdentityCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core.parseXmlBody)(output.body, context);
  let contents = {};
  contents = de_GetCallerIdentityResponse(data.GetCallerIdentityResult, context);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_GetCallerIdentityCommand");
var de_GetFederationTokenCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core.parseXmlBody)(output.body, context);
  let contents = {};
  contents = de_GetFederationTokenResponse(data.GetFederationTokenResult, context);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_GetFederationTokenCommand");
var de_GetSessionTokenCommand = /* @__PURE__ */ __name(async (output, context) => {
  if (output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const data = await (0, import_core.parseXmlBody)(output.body, context);
  let contents = {};
  contents = de_GetSessionTokenResponse(data.GetSessionTokenResult, context);
  const response = {
    $metadata: deserializeMetadata(output),
    ...contents
  };
  return response;
}, "de_GetSessionTokenCommand");
var de_CommandError = /* @__PURE__ */ __name(async (output, context) => {
  const parsedOutput = {
    ...output,
    body: await (0, import_core.parseXmlErrorBody)(output.body, context)
  };
  const errorCode = loadQueryErrorCode(output, parsedOutput.body);
  switch (errorCode) {
    case "ExpiredTokenException":
    case "com.amazonaws.sts#ExpiredTokenException":
      throw await de_ExpiredTokenExceptionRes(parsedOutput, context);
    case "MalformedPolicyDocument":
    case "com.amazonaws.sts#MalformedPolicyDocumentException":
      throw await de_MalformedPolicyDocumentExceptionRes(parsedOutput, context);
    case "PackedPolicyTooLarge":
    case "com.amazonaws.sts#PackedPolicyTooLargeException":
      throw await de_PackedPolicyTooLargeExceptionRes(parsedOutput, context);
    case "RegionDisabledException":
    case "com.amazonaws.sts#RegionDisabledException":
      throw await de_RegionDisabledExceptionRes(parsedOutput, context);
    case "IDPRejectedClaim":
    case "com.amazonaws.sts#IDPRejectedClaimException":
      throw await de_IDPRejectedClaimExceptionRes(parsedOutput, context);
    case "InvalidIdentityToken":
    case "com.amazonaws.sts#InvalidIdentityTokenException":
      throw await de_InvalidIdentityTokenExceptionRes(parsedOutput, context);
    case "IDPCommunicationError":
    case "com.amazonaws.sts#IDPCommunicationErrorException":
      throw await de_IDPCommunicationErrorExceptionRes(parsedOutput, context);
    case "InvalidAuthorizationMessageException":
    case "com.amazonaws.sts#InvalidAuthorizationMessageException":
      throw await de_InvalidAuthorizationMessageExceptionRes(parsedOutput, context);
    default:
      const parsedBody = parsedOutput.body;
      return throwDefaultError({
        output,
        parsedBody: parsedBody.Error,
        errorCode
      });
  }
}, "de_CommandError");
var de_ExpiredTokenExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = de_ExpiredTokenException(body.Error, context);
  const exception = new ExpiredTokenException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_ExpiredTokenExceptionRes");
var de_IDPCommunicationErrorExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = de_IDPCommunicationErrorException(body.Error, context);
  const exception = new IDPCommunicationErrorException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_IDPCommunicationErrorExceptionRes");
var de_IDPRejectedClaimExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = de_IDPRejectedClaimException(body.Error, context);
  const exception = new IDPRejectedClaimException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_IDPRejectedClaimExceptionRes");
var de_InvalidAuthorizationMessageExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = de_InvalidAuthorizationMessageException(body.Error, context);
  const exception = new InvalidAuthorizationMessageException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_InvalidAuthorizationMessageExceptionRes");
var de_InvalidIdentityTokenExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = de_InvalidIdentityTokenException(body.Error, context);
  const exception = new InvalidIdentityTokenException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_InvalidIdentityTokenExceptionRes");
var de_MalformedPolicyDocumentExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = de_MalformedPolicyDocumentException(body.Error, context);
  const exception = new MalformedPolicyDocumentException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_MalformedPolicyDocumentExceptionRes");
var de_PackedPolicyTooLargeExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = de_PackedPolicyTooLargeException(body.Error, context);
  const exception = new PackedPolicyTooLargeException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_PackedPolicyTooLargeExceptionRes");
var de_RegionDisabledExceptionRes = /* @__PURE__ */ __name(async (parsedOutput, context) => {
  const body = parsedOutput.body;
  const deserialized = de_RegionDisabledException(body.Error, context);
  const exception = new RegionDisabledException({
    $metadata: deserializeMetadata(parsedOutput),
    ...deserialized
  });
  return (0, import_smithy_client.decorateServiceException)(exception, body);
}, "de_RegionDisabledExceptionRes");
var se_AssumeRoleRequest = /* @__PURE__ */ __name((input, context) => {
  var _a2, _b, _c, _d;
  const entries = {};
  if (input[_RA] != null) {
    entries[_RA] = input[_RA];
  }
  if (input[_RSN] != null) {
    entries[_RSN] = input[_RSN];
  }
  if (input[_PA] != null) {
    const memberEntries = se_policyDescriptorListType(input[_PA], context);
    if (((_a2 = input[_PA]) == null ? void 0 : _a2.length) === 0) {
      entries.PolicyArns = [];
    }
    Object.entries(memberEntries).forEach(([key, value]) => {
      const loc = `PolicyArns.${key}`;
      entries[loc] = value;
    });
  }
  if (input[_P] != null) {
    entries[_P] = input[_P];
  }
  if (input[_DS] != null) {
    entries[_DS] = input[_DS];
  }
  if (input[_T] != null) {
    const memberEntries = se_tagListType(input[_T], context);
    if (((_b = input[_T]) == null ? void 0 : _b.length) === 0) {
      entries.Tags = [];
    }
    Object.entries(memberEntries).forEach(([key, value]) => {
      const loc = `Tags.${key}`;
      entries[loc] = value;
    });
  }
  if (input[_TTK] != null) {
    const memberEntries = se_tagKeyListType(input[_TTK], context);
    if (((_c = input[_TTK]) == null ? void 0 : _c.length) === 0) {
      entries.TransitiveTagKeys = [];
    }
    Object.entries(memberEntries).forEach(([key, value]) => {
      const loc = `TransitiveTagKeys.${key}`;
      entries[loc] = value;
    });
  }
  if (input[_EI] != null) {
    entries[_EI] = input[_EI];
  }
  if (input[_SN] != null) {
    entries[_SN] = input[_SN];
  }
  if (input[_TC] != null) {
    entries[_TC] = input[_TC];
  }
  if (input[_SI] != null) {
    entries[_SI] = input[_SI];
  }
  if (input[_PC] != null) {
    const memberEntries = se_ProvidedContextsListType(input[_PC], context);
    if (((_d = input[_PC]) == null ? void 0 : _d.length) === 0) {
      entries.ProvidedContexts = [];
    }
    Object.entries(memberEntries).forEach(([key, value]) => {
      const loc = `ProvidedContexts.${key}`;
      entries[loc] = value;
    });
  }
  return entries;
}, "se_AssumeRoleRequest");
var se_AssumeRoleWithSAMLRequest = /* @__PURE__ */ __name((input, context) => {
  var _a2;
  const entries = {};
  if (input[_RA] != null) {
    entries[_RA] = input[_RA];
  }
  if (input[_PAr] != null) {
    entries[_PAr] = input[_PAr];
  }
  if (input[_SAMLA] != null) {
    entries[_SAMLA] = input[_SAMLA];
  }
  if (input[_PA] != null) {
    const memberEntries = se_policyDescriptorListType(input[_PA], context);
    if (((_a2 = input[_PA]) == null ? void 0 : _a2.length) === 0) {
      entries.PolicyArns = [];
    }
    Object.entries(memberEntries).forEach(([key, value]) => {
      const loc = `PolicyArns.${key}`;
      entries[loc] = value;
    });
  }
  if (input[_P] != null) {
    entries[_P] = input[_P];
  }
  if (input[_DS] != null) {
    entries[_DS] = input[_DS];
  }
  return entries;
}, "se_AssumeRoleWithSAMLRequest");
var se_AssumeRoleWithWebIdentityRequest = /* @__PURE__ */ __name((input, context) => {
  var _a2;
  const entries = {};
  if (input[_RA] != null) {
    entries[_RA] = input[_RA];
  }
  if (input[_RSN] != null) {
    entries[_RSN] = input[_RSN];
  }
  if (input[_WIT] != null) {
    entries[_WIT] = input[_WIT];
  }
  if (input[_PI] != null) {
    entries[_PI] = input[_PI];
  }
  if (input[_PA] != null) {
    const memberEntries = se_policyDescriptorListType(input[_PA], context);
    if (((_a2 = input[_PA]) == null ? void 0 : _a2.length) === 0) {
      entries.PolicyArns = [];
    }
    Object.entries(memberEntries).forEach(([key, value]) => {
      const loc = `PolicyArns.${key}`;
      entries[loc] = value;
    });
  }
  if (input[_P] != null) {
    entries[_P] = input[_P];
  }
  if (input[_DS] != null) {
    entries[_DS] = input[_DS];
  }
  return entries;
}, "se_AssumeRoleWithWebIdentityRequest");
var se_DecodeAuthorizationMessageRequest = /* @__PURE__ */ __name((input, context) => {
  const entries = {};
  if (input[_EM] != null) {
    entries[_EM] = input[_EM];
  }
  return entries;
}, "se_DecodeAuthorizationMessageRequest");
var se_GetAccessKeyInfoRequest = /* @__PURE__ */ __name((input, context) => {
  const entries = {};
  if (input[_AKI] != null) {
    entries[_AKI] = input[_AKI];
  }
  return entries;
}, "se_GetAccessKeyInfoRequest");
var se_GetCallerIdentityRequest = /* @__PURE__ */ __name((input, context) => {
  const entries = {};
  return entries;
}, "se_GetCallerIdentityRequest");
var se_GetFederationTokenRequest = /* @__PURE__ */ __name((input, context) => {
  var _a2, _b;
  const entries = {};
  if (input[_N] != null) {
    entries[_N] = input[_N];
  }
  if (input[_P] != null) {
    entries[_P] = input[_P];
  }
  if (input[_PA] != null) {
    const memberEntries = se_policyDescriptorListType(input[_PA], context);
    if (((_a2 = input[_PA]) == null ? void 0 : _a2.length) === 0) {
      entries.PolicyArns = [];
    }
    Object.entries(memberEntries).forEach(([key, value]) => {
      const loc = `PolicyArns.${key}`;
      entries[loc] = value;
    });
  }
  if (input[_DS] != null) {
    entries[_DS] = input[_DS];
  }
  if (input[_T] != null) {
    const memberEntries = se_tagListType(input[_T], context);
    if (((_b = input[_T]) == null ? void 0 : _b.length) === 0) {
      entries.Tags = [];
    }
    Object.entries(memberEntries).forEach(([key, value]) => {
      const loc = `Tags.${key}`;
      entries[loc] = value;
    });
  }
  return entries;
}, "se_GetFederationTokenRequest");
var se_GetSessionTokenRequest = /* @__PURE__ */ __name((input, context) => {
  const entries = {};
  if (input[_DS] != null) {
    entries[_DS] = input[_DS];
  }
  if (input[_SN] != null) {
    entries[_SN] = input[_SN];
  }
  if (input[_TC] != null) {
    entries[_TC] = input[_TC];
  }
  return entries;
}, "se_GetSessionTokenRequest");
var se_policyDescriptorListType = /* @__PURE__ */ __name((input, context) => {
  const entries = {};
  let counter = 1;
  for (const entry of input) {
    if (entry === null) {
      continue;
    }
    const memberEntries = se_PolicyDescriptorType(entry, context);
    Object.entries(memberEntries).forEach(([key, value]) => {
      entries[`member.${counter}.${key}`] = value;
    });
    counter++;
  }
  return entries;
}, "se_policyDescriptorListType");
var se_PolicyDescriptorType = /* @__PURE__ */ __name((input, context) => {
  const entries = {};
  if (input[_a] != null) {
    entries[_a] = input[_a];
  }
  return entries;
}, "se_PolicyDescriptorType");
var se_ProvidedContext = /* @__PURE__ */ __name((input, context) => {
  const entries = {};
  if (input[_PAro] != null) {
    entries[_PAro] = input[_PAro];
  }
  if (input[_CA] != null) {
    entries[_CA] = input[_CA];
  }
  return entries;
}, "se_ProvidedContext");
var se_ProvidedContextsListType = /* @__PURE__ */ __name((input, context) => {
  const entries = {};
  let counter = 1;
  for (const entry of input) {
    if (entry === null) {
      continue;
    }
    const memberEntries = se_ProvidedContext(entry, context);
    Object.entries(memberEntries).forEach(([key, value]) => {
      entries[`member.${counter}.${key}`] = value;
    });
    counter++;
  }
  return entries;
}, "se_ProvidedContextsListType");
var se_Tag = /* @__PURE__ */ __name((input, context) => {
  const entries = {};
  if (input[_K] != null) {
    entries[_K] = input[_K];
  }
  if (input[_Va] != null) {
    entries[_Va] = input[_Va];
  }
  return entries;
}, "se_Tag");
var se_tagKeyListType = /* @__PURE__ */ __name((input, context) => {
  const entries = {};
  let counter = 1;
  for (const entry of input) {
    if (entry === null) {
      continue;
    }
    entries[`member.${counter}`] = entry;
    counter++;
  }
  return entries;
}, "se_tagKeyListType");
var se_tagListType = /* @__PURE__ */ __name((input, context) => {
  const entries = {};
  let counter = 1;
  for (const entry of input) {
    if (entry === null) {
      continue;
    }
    const memberEntries = se_Tag(entry, context);
    Object.entries(memberEntries).forEach(([key, value]) => {
      entries[`member.${counter}.${key}`] = value;
    });
    counter++;
  }
  return entries;
}, "se_tagListType");
var de_AssumedRoleUser = /* @__PURE__ */ __name((output, context) => {
  const contents = {};
  if (output[_ARI] != null) {
    contents[_ARI] = (0, import_smithy_client.expectString)(output[_ARI]);
  }
  if (output[_Ar] != null) {
    contents[_Ar] = (0, import_smithy_client.expectString)(output[_Ar]);
  }
  return contents;
}, "de_AssumedRoleUser");
var de_AssumeRoleResponse = /* @__PURE__ */ __name((output, context) => {
  const contents = {};
  if (output[_C] != null) {
    contents[_C] = de_Credentials(output[_C], context);
  }
  if (output[_ARU] != null) {
    contents[_ARU] = de_AssumedRoleUser(output[_ARU], context);
  }
  if (output[_PPS] != null) {
    contents[_PPS] = (0, import_smithy_client.strictParseInt32)(output[_PPS]);
  }
  if (output[_SI] != null) {
    contents[_SI] = (0, import_smithy_client.expectString)(output[_SI]);
  }
  return contents;
}, "de_AssumeRoleResponse");
var de_AssumeRoleWithSAMLResponse = /* @__PURE__ */ __name((output, context) => {
  const contents = {};
  if (output[_C] != null) {
    contents[_C] = de_Credentials(output[_C], context);
  }
  if (output[_ARU] != null) {
    contents[_ARU] = de_AssumedRoleUser(output[_ARU], context);
  }
  if (output[_PPS] != null) {
    contents[_PPS] = (0, import_smithy_client.strictParseInt32)(output[_PPS]);
  }
  if (output[_S] != null) {
    contents[_S] = (0, import_smithy_client.expectString)(output[_S]);
  }
  if (output[_ST] != null) {
    contents[_ST] = (0, import_smithy_client.expectString)(output[_ST]);
  }
  if (output[_I] != null) {
    contents[_I] = (0, import_smithy_client.expectString)(output[_I]);
  }
  if (output[_Au] != null) {
    contents[_Au] = (0, import_smithy_client.expectString)(output[_Au]);
  }
  if (output[_NQ] != null) {
    contents[_NQ] = (0, import_smithy_client.expectString)(output[_NQ]);
  }
  if (output[_SI] != null) {
    contents[_SI] = (0, import_smithy_client.expectString)(output[_SI]);
  }
  return contents;
}, "de_AssumeRoleWithSAMLResponse");
var de_AssumeRoleWithWebIdentityResponse = /* @__PURE__ */ __name((output, context) => {
  const contents = {};
  if (output[_C] != null) {
    contents[_C] = de_Credentials(output[_C], context);
  }
  if (output[_SFWIT] != null) {
    contents[_SFWIT] = (0, import_smithy_client.expectString)(output[_SFWIT]);
  }
  if (output[_ARU] != null) {
    contents[_ARU] = de_AssumedRoleUser(output[_ARU], context);
  }
  if (output[_PPS] != null) {
    contents[_PPS] = (0, import_smithy_client.strictParseInt32)(output[_PPS]);
  }
  if (output[_Pr] != null) {
    contents[_Pr] = (0, import_smithy_client.expectString)(output[_Pr]);
  }
  if (output[_Au] != null) {
    contents[_Au] = (0, import_smithy_client.expectString)(output[_Au]);
  }
  if (output[_SI] != null) {
    contents[_SI] = (0, import_smithy_client.expectString)(output[_SI]);
  }
  return contents;
}, "de_AssumeRoleWithWebIdentityResponse");
var de_Credentials = /* @__PURE__ */ __name((output, context) => {
  const contents = {};
  if (output[_AKI] != null) {
    contents[_AKI] = (0, import_smithy_client.expectString)(output[_AKI]);
  }
  if (output[_SAK] != null) {
    contents[_SAK] = (0, import_smithy_client.expectString)(output[_SAK]);
  }
  if (output[_STe] != null) {
    contents[_STe] = (0, import_smithy_client.expectString)(output[_STe]);
  }
  if (output[_E] != null) {
    contents[_E] = (0, import_smithy_client.expectNonNull)((0, import_smithy_client.parseRfc3339DateTimeWithOffset)(output[_E]));
  }
  return contents;
}, "de_Credentials");
var de_DecodeAuthorizationMessageResponse = /* @__PURE__ */ __name((output, context) => {
  const contents = {};
  if (output[_DM] != null) {
    contents[_DM] = (0, import_smithy_client.expectString)(output[_DM]);
  }
  return contents;
}, "de_DecodeAuthorizationMessageResponse");
var de_ExpiredTokenException = /* @__PURE__ */ __name((output, context) => {
  const contents = {};
  if (output[_m] != null) {
    contents[_m] = (0, import_smithy_client.expectString)(output[_m]);
  }
  return contents;
}, "de_ExpiredTokenException");
var de_FederatedUser = /* @__PURE__ */ __name((output, context) => {
  const contents = {};
  if (output[_FUI] != null) {
    contents[_FUI] = (0, import_smithy_client.expectString)(output[_FUI]);
  }
  if (output[_Ar] != null) {
    contents[_Ar] = (0, import_smithy_client.expectString)(output[_Ar]);
  }
  return contents;
}, "de_FederatedUser");
var de_GetAccessKeyInfoResponse = /* @__PURE__ */ __name((output, context) => {
  const contents = {};
  if (output[_Ac] != null) {
    contents[_Ac] = (0, import_smithy_client.expectString)(output[_Ac]);
  }
  return contents;
}, "de_GetAccessKeyInfoResponse");
var de_GetCallerIdentityResponse = /* @__PURE__ */ __name((output, context) => {
  const contents = {};
  if (output[_UI] != null) {
    contents[_UI] = (0, import_smithy_client.expectString)(output[_UI]);
  }
  if (output[_Ac] != null) {
    contents[_Ac] = (0, import_smithy_client.expectString)(output[_Ac]);
  }
  if (output[_Ar] != null) {
    contents[_Ar] = (0, import_smithy_client.expectString)(output[_Ar]);
  }
  return contents;
}, "de_GetCallerIdentityResponse");
var de_GetFederationTokenResponse = /* @__PURE__ */ __name((output, context) => {
  const contents = {};
  if (output[_C] != null) {
    contents[_C] = de_Credentials(output[_C], context);
  }
  if (output[_FU] != null) {
    contents[_FU] = de_FederatedUser(output[_FU], context);
  }
  if (output[_PPS] != null) {
    contents[_PPS] = (0, import_smithy_client.strictParseInt32)(output[_PPS]);
  }
  return contents;
}, "de_GetFederationTokenResponse");
var de_GetSessionTokenResponse = /* @__PURE__ */ __name((output, context) => {
  const contents = {};
  if (output[_C] != null) {
    contents[_C] = de_Credentials(output[_C], context);
  }
  return contents;
}, "de_GetSessionTokenResponse");
var de_IDPCommunicationErrorException = /* @__PURE__ */ __name((output, context) => {
  const contents = {};
  if (output[_m] != null) {
    contents[_m] = (0, import_smithy_client.expectString)(output[_m]);
  }
  return contents;
}, "de_IDPCommunicationErrorException");
var de_IDPRejectedClaimException = /* @__PURE__ */ __name((output, context) => {
  const contents = {};
  if (output[_m] != null) {
    contents[_m] = (0, import_smithy_client.expectString)(output[_m]);
  }
  return contents;
}, "de_IDPRejectedClaimException");
var de_InvalidAuthorizationMessageException = /* @__PURE__ */ __name((output, context) => {
  const contents = {};
  if (output[_m] != null) {
    contents[_m] = (0, import_smithy_client.expectString)(output[_m]);
  }
  return contents;
}, "de_InvalidAuthorizationMessageException");
var de_InvalidIdentityTokenException = /* @__PURE__ */ __name((output, context) => {
  const contents = {};
  if (output[_m] != null) {
    contents[_m] = (0, import_smithy_client.expectString)(output[_m]);
  }
  return contents;
}, "de_InvalidIdentityTokenException");
var de_MalformedPolicyDocumentException = /* @__PURE__ */ __name((output, context) => {
  const contents = {};
  if (output[_m] != null) {
    contents[_m] = (0, import_smithy_client.expectString)(output[_m]);
  }
  return contents;
}, "de_MalformedPolicyDocumentException");
var de_PackedPolicyTooLargeException = /* @__PURE__ */ __name((output, context) => {
  const contents = {};
  if (output[_m] != null) {
    contents[_m] = (0, import_smithy_client.expectString)(output[_m]);
  }
  return contents;
}, "de_PackedPolicyTooLargeException");
var de_RegionDisabledException = /* @__PURE__ */ __name((output, context) => {
  const contents = {};
  if (output[_m] != null) {
    contents[_m] = (0, import_smithy_client.expectString)(output[_m]);
  }
  return contents;
}, "de_RegionDisabledException");
var deserializeMetadata = /* @__PURE__ */ __name((output) => ({
  httpStatusCode: output.statusCode,
  requestId: output.headers["x-amzn-requestid"] ?? output.headers["x-amzn-request-id"] ?? output.headers["x-amz-request-id"],
  extendedRequestId: output.headers["x-amz-id-2"],
  cfId: output.headers["x-amz-cf-id"]
}), "deserializeMetadata");
var throwDefaultError = (0, import_smithy_client.withBaseException)(STSServiceException);
var buildHttpRpcRequest = /* @__PURE__ */ __name(async (context, headers, path, resolvedHostname, body) => {
  const { hostname, protocol = "https", port, path: basePath } = await context.endpoint();
  const contents = {
    protocol,
    hostname,
    port,
    method: "POST",
    path: basePath.endsWith("/") ? basePath.slice(0, -1) + path : basePath + path,
    headers
  };
  if (resolvedHostname !== void 0) {
    contents.hostname = resolvedHostname;
  }
  if (body !== void 0) {
    contents.body = body;
  }
  return new import_protocol_http.HttpRequest(contents);
}, "buildHttpRpcRequest");
var SHARED_HEADERS = {
  "content-type": "application/x-www-form-urlencoded"
};
var _ = "2011-06-15";
var _A = "Action";
var _AKI = "AccessKeyId";
var _AR = "AssumeRole";
var _ARI = "AssumedRoleId";
var _ARU = "AssumedRoleUser";
var _ARWSAML = "AssumeRoleWithSAML";
var _ARWWI = "AssumeRoleWithWebIdentity";
var _Ac = "Account";
var _Ar = "Arn";
var _Au = "Audience";
var _C = "Credentials";
var _CA = "ContextAssertion";
var _DAM = "DecodeAuthorizationMessage";
var _DM = "DecodedMessage";
var _DS = "DurationSeconds";
var _E = "Expiration";
var _EI = "ExternalId";
var _EM = "EncodedMessage";
var _FU = "FederatedUser";
var _FUI = "FederatedUserId";
var _GAKI = "GetAccessKeyInfo";
var _GCI = "GetCallerIdentity";
var _GFT = "GetFederationToken";
var _GST = "GetSessionToken";
var _I = "Issuer";
var _K = "Key";
var _N = "Name";
var _NQ = "NameQualifier";
var _P = "Policy";
var _PA = "PolicyArns";
var _PAr = "PrincipalArn";
var _PAro = "ProviderArn";
var _PC = "ProvidedContexts";
var _PI = "ProviderId";
var _PPS = "PackedPolicySize";
var _Pr = "Provider";
var _RA = "RoleArn";
var _RSN = "RoleSessionName";
var _S = "Subject";
var _SAK = "SecretAccessKey";
var _SAMLA = "SAMLAssertion";
var _SFWIT = "SubjectFromWebIdentityToken";
var _SI = "SourceIdentity";
var _SN = "SerialNumber";
var _ST = "SubjectType";
var _STe = "SessionToken";
var _T = "Tags";
var _TC = "TokenCode";
var _TTK = "TransitiveTagKeys";
var _UI = "UserId";
var _V = "Version";
var _Va = "Value";
var _WIT = "WebIdentityToken";
var _a = "arn";
var _m = "message";
var buildFormUrlencodedString = /* @__PURE__ */ __name((formEntries) => Object.entries(formEntries).map(([key, value]) => (0, import_smithy_client.extendedEncodeURIComponent)(key) + "=" + (0, import_smithy_client.extendedEncodeURIComponent)(value)).join("&"), "buildFormUrlencodedString");
var loadQueryErrorCode = /* @__PURE__ */ __name((output, data) => {
  var _a2;
  if (((_a2 = data.Error) == null ? void 0 : _a2.Code) !== void 0) {
    return data.Error.Code;
  }
  if (output.statusCode == 404) {
    return "NotFound";
  }
}, "loadQueryErrorCode");

// src/commands/AssumeRoleCommand.ts
var _AssumeRoleCommand = class _AssumeRoleCommand extends import_smithy_client.Command.classBuilder().ep({
  ...import_EndpointParameters.commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AWSSecurityTokenServiceV20110615", "AssumeRole", {}).n("STSClient", "AssumeRoleCommand").f(void 0, AssumeRoleResponseFilterSensitiveLog).ser(se_AssumeRoleCommand).de(de_AssumeRoleCommand).build() {
};
__name(_AssumeRoleCommand, "AssumeRoleCommand");
var AssumeRoleCommand = _AssumeRoleCommand;

// src/commands/AssumeRoleWithSAMLCommand.ts



var import_EndpointParameters2 = __nccwpck_require__(510);
var _AssumeRoleWithSAMLCommand = class _AssumeRoleWithSAMLCommand extends import_smithy_client.Command.classBuilder().ep({
  ...import_EndpointParameters2.commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AWSSecurityTokenServiceV20110615", "AssumeRoleWithSAML", {}).n("STSClient", "AssumeRoleWithSAMLCommand").f(AssumeRoleWithSAMLRequestFilterSensitiveLog, AssumeRoleWithSAMLResponseFilterSensitiveLog).ser(se_AssumeRoleWithSAMLCommand).de(de_AssumeRoleWithSAMLCommand).build() {
};
__name(_AssumeRoleWithSAMLCommand, "AssumeRoleWithSAMLCommand");
var AssumeRoleWithSAMLCommand = _AssumeRoleWithSAMLCommand;

// src/commands/AssumeRoleWithWebIdentityCommand.ts



var import_EndpointParameters3 = __nccwpck_require__(510);
var _AssumeRoleWithWebIdentityCommand = class _AssumeRoleWithWebIdentityCommand extends import_smithy_client.Command.classBuilder().ep({
  ...import_EndpointParameters3.commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AWSSecurityTokenServiceV20110615", "AssumeRoleWithWebIdentity", {}).n("STSClient", "AssumeRoleWithWebIdentityCommand").f(AssumeRoleWithWebIdentityRequestFilterSensitiveLog, AssumeRoleWithWebIdentityResponseFilterSensitiveLog).ser(se_AssumeRoleWithWebIdentityCommand).de(de_AssumeRoleWithWebIdentityCommand).build() {
};
__name(_AssumeRoleWithWebIdentityCommand, "AssumeRoleWithWebIdentityCommand");
var AssumeRoleWithWebIdentityCommand = _AssumeRoleWithWebIdentityCommand;

// src/commands/DecodeAuthorizationMessageCommand.ts



var import_EndpointParameters4 = __nccwpck_require__(510);
var _DecodeAuthorizationMessageCommand = class _DecodeAuthorizationMessageCommand extends import_smithy_client.Command.classBuilder().ep({
  ...import_EndpointParameters4.commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AWSSecurityTokenServiceV20110615", "DecodeAuthorizationMessage", {}).n("STSClient", "DecodeAuthorizationMessageCommand").f(void 0, void 0).ser(se_DecodeAuthorizationMessageCommand).de(de_DecodeAuthorizationMessageCommand).build() {
};
__name(_DecodeAuthorizationMessageCommand, "DecodeAuthorizationMessageCommand");
var DecodeAuthorizationMessageCommand = _DecodeAuthorizationMessageCommand;

// src/commands/GetAccessKeyInfoCommand.ts



var import_EndpointParameters5 = __nccwpck_require__(510);
var _GetAccessKeyInfoCommand = class _GetAccessKeyInfoCommand extends import_smithy_client.Command.classBuilder().ep({
  ...import_EndpointParameters5.commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AWSSecurityTokenServiceV20110615", "GetAccessKeyInfo", {}).n("STSClient", "GetAccessKeyInfoCommand").f(void 0, void 0).ser(se_GetAccessKeyInfoCommand).de(de_GetAccessKeyInfoCommand).build() {
};
__name(_GetAccessKeyInfoCommand, "GetAccessKeyInfoCommand");
var GetAccessKeyInfoCommand = _GetAccessKeyInfoCommand;

// src/commands/GetCallerIdentityCommand.ts



var import_EndpointParameters6 = __nccwpck_require__(510);
var _GetCallerIdentityCommand = class _GetCallerIdentityCommand extends import_smithy_client.Command.classBuilder().ep({
  ...import_EndpointParameters6.commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AWSSecurityTokenServiceV20110615", "GetCallerIdentity", {}).n("STSClient", "GetCallerIdentityCommand").f(void 0, void 0).ser(se_GetCallerIdentityCommand).de(de_GetCallerIdentityCommand).build() {
};
__name(_GetCallerIdentityCommand, "GetCallerIdentityCommand");
var GetCallerIdentityCommand = _GetCallerIdentityCommand;

// src/commands/GetFederationTokenCommand.ts



var import_EndpointParameters7 = __nccwpck_require__(510);
var _GetFederationTokenCommand = class _GetFederationTokenCommand extends import_smithy_client.Command.classBuilder().ep({
  ...import_EndpointParameters7.commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AWSSecurityTokenServiceV20110615", "GetFederationToken", {}).n("STSClient", "GetFederationTokenCommand").f(void 0, GetFederationTokenResponseFilterSensitiveLog).ser(se_GetFederationTokenCommand).de(de_GetFederationTokenCommand).build() {
};
__name(_GetFederationTokenCommand, "GetFederationTokenCommand");
var GetFederationTokenCommand = _GetFederationTokenCommand;

// src/commands/GetSessionTokenCommand.ts



var import_EndpointParameters8 = __nccwpck_require__(510);
var _GetSessionTokenCommand = class _GetSessionTokenCommand extends import_smithy_client.Command.classBuilder().ep({
  ...import_EndpointParameters8.commonParams
}).m(function(Command, cs, config, o) {
  return [
    (0, import_middleware_serde.getSerdePlugin)(config, this.serialize, this.deserialize),
    (0, import_middleware_endpoint.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())
  ];
}).s("AWSSecurityTokenServiceV20110615", "GetSessionToken", {}).n("STSClient", "GetSessionTokenCommand").f(void 0, GetSessionTokenResponseFilterSensitiveLog).ser(se_GetSessionTokenCommand).de(de_GetSessionTokenCommand).build() {
};
__name(_GetSessionTokenCommand, "GetSessionTokenCommand");
var GetSessionTokenCommand = _GetSessionTokenCommand;

// src/STS.ts
var import_STSClient = __nccwpck_require__(4195);
var commands = {
  AssumeRoleCommand,
  AssumeRoleWithSAMLCommand,
  AssumeRoleWithWebIdentityCommand,
  DecodeAuthorizationMessageCommand,
  GetAccessKeyInfoCommand,
  GetCallerIdentityCommand,
  GetFederationTokenCommand,
  GetSessionTokenCommand
};
var _STS = class _STS extends import_STSClient.STSClient {
};
__name(_STS, "STS");
var STS = _STS;
(0, import_smithy_client.createAggregatedClient)(commands, STS);

// src/index.ts
var import_EndpointParameters9 = __nccwpck_require__(510);

// src/defaultStsRoleAssumers.ts
var ASSUME_ROLE_DEFAULT_REGION = "us-east-1";
var getAccountIdFromAssumedRoleUser = /* @__PURE__ */ __name((assumedRoleUser) => {
  if (typeof (assumedRoleUser == null ? void 0 : assumedRoleUser.Arn) === "string") {
    const arnComponents = assumedRoleUser.Arn.split(":");
    if (arnComponents.length > 4 && arnComponents[4] !== "") {
      return arnComponents[4];
    }
  }
  return void 0;
}, "getAccountIdFromAssumedRoleUser");
var resolveRegion = /* @__PURE__ */ __name(async (_region, _parentRegion, credentialProviderLogger) => {
  var _a2;
  const region = typeof _region === "function" ? await _region() : _region;
  const parentRegion = typeof _parentRegion === "function" ? await _parentRegion() : _parentRegion;
  (_a2 = credentialProviderLogger == null ? void 0 : credentialProviderLogger.debug) == null ? void 0 : _a2.call(
    credentialProviderLogger,
    "@aws-sdk/client-sts::resolveRegion",
    "accepting first of:",
    `${region} (provider)`,
    `${parentRegion} (parent client)`,
    `${ASSUME_ROLE_DEFAULT_REGION} (STS default)`
  );
  return region ?? parentRegion ?? ASSUME_ROLE_DEFAULT_REGION;
}, "resolveRegion");
var getDefaultRoleAssumer = /* @__PURE__ */ __name((stsOptions, stsClientCtor) => {
  let stsClient;
  let closureSourceCreds;
  return async (sourceCreds, params) => {
    var _a2, _b, _c;
    closureSourceCreds = sourceCreds;
    if (!stsClient) {
      const {
        logger = (_a2 = stsOptions == null ? void 0 : stsOptions.parentClientConfig) == null ? void 0 : _a2.logger,
        region,
        requestHandler = (_b = stsOptions == null ? void 0 : stsOptions.parentClientConfig) == null ? void 0 : _b.requestHandler,
        credentialProviderLogger
      } = stsOptions;
      const resolvedRegion = await resolveRegion(
        region,
        (_c = stsOptions == null ? void 0 : stsOptions.parentClientConfig) == null ? void 0 : _c.region,
        credentialProviderLogger
      );
      stsClient = new stsClientCtor({
        // A hack to make sts client uses the credential in current closure.
        credentialDefaultProvider: () => async () => closureSourceCreds,
        region: resolvedRegion,
        requestHandler,
        logger
      });
    }
    const { Credentials: Credentials2, AssumedRoleUser: AssumedRoleUser2 } = await stsClient.send(new AssumeRoleCommand(params));
    if (!Credentials2 || !Credentials2.AccessKeyId || !Credentials2.SecretAccessKey) {
      throw new Error(`Invalid response from STS.assumeRole call with role ${params.RoleArn}`);
    }
    const accountId = getAccountIdFromAssumedRoleUser(AssumedRoleUser2);
    return {
      accessKeyId: Credentials2.AccessKeyId,
      secretAccessKey: Credentials2.SecretAccessKey,
      sessionToken: Credentials2.SessionToken,
      expiration: Credentials2.Expiration,
      // TODO(credentialScope): access normally when shape is updated.
      ...Credentials2.CredentialScope && { credentialScope: Credentials2.CredentialScope },
      ...accountId && { accountId }
    };
  };
}, "getDefaultRoleAssumer");
var getDefaultRoleAssumerWithWebIdentity = /* @__PURE__ */ __name((stsOptions, stsClientCtor) => {
  let stsClient;
  return async (params) => {
    var _a2, _b, _c;
    if (!stsClient) {
      const {
        logger = (_a2 = stsOptions == null ? void 0 : stsOptions.parentClientConfig) == null ? void 0 : _a2.logger,
        region,
        requestHandler = (_b = stsOptions == null ? void 0 : stsOptions.parentClientConfig) == null ? void 0 : _b.requestHandler,
        credentialProviderLogger
      } = stsOptions;
      const resolvedRegion = await resolveRegion(
        region,
        (_c = stsOptions == null ? void 0 : stsOptions.parentClientConfig) == null ? void 0 : _c.region,
        credentialProviderLogger
      );
      stsClient = new stsClientCtor({
        region: resolvedRegion,
        requestHandler,
        logger
      });
    }
    const { Credentials: Credentials2, AssumedRoleUser: AssumedRoleUser2 } = await stsClient.send(new AssumeRoleWithWebIdentityCommand(params));
    if (!Credentials2 || !Credentials2.AccessKeyId || !Credentials2.SecretAccessKey) {
      throw new Error(`Invalid response from STS.assumeRoleWithWebIdentity call with role ${params.RoleArn}`);
    }
    const accountId = getAccountIdFromAssumedRoleUser(AssumedRoleUser2);
    return {
      accessKeyId: Credentials2.AccessKeyId,
      secretAccessKey: Credentials2.SecretAccessKey,
      sessionToken: Credentials2.SessionToken,
      expiration: Credentials2.Expiration,
      // TODO(credentialScope): access normally when shape is updated.
      ...Credentials2.CredentialScope && { credentialScope: Credentials2.CredentialScope },
      ...accountId && { accountId }
    };
  };
}, "getDefaultRoleAssumerWithWebIdentity");

// src/defaultRoleAssumers.ts
var import_STSClient2 = __nccwpck_require__(4195);
var getCustomizableStsClientCtor = /* @__PURE__ */ __name((baseCtor, customizations) => {
  var _a2;
  if (!customizations)
    return baseCtor;
  else
    return _a2 = class extends baseCtor {
      constructor(config) {
        super(config);
        for (const customization of customizations) {
          this.middlewareStack.use(customization);
        }
      }
    }, __name(_a2, "CustomizableSTSClient"), _a2;
}, "getCustomizableStsClientCtor");
var getDefaultRoleAssumer2 = /* @__PURE__ */ __name((stsOptions = {}, stsPlugins) => getDefaultRoleAssumer(stsOptions, getCustomizableStsClientCtor(import_STSClient2.STSClient, stsPlugins)), "getDefaultRoleAssumer");
var getDefaultRoleAssumerWithWebIdentity2 = /* @__PURE__ */ __name((stsOptions = {}, stsPlugins) => getDefaultRoleAssumerWithWebIdentity(stsOptions, getCustomizableStsClientCtor(import_STSClient2.STSClient, stsPlugins)), "getDefaultRoleAssumerWithWebIdentity");
var decorateDefaultCredentialProvider = /* @__PURE__ */ __name((provider) => (input) => provider({
  roleAssumer: getDefaultRoleAssumer2(input),
  roleAssumerWithWebIdentity: getDefaultRoleAssumerWithWebIdentity2(input),
  ...input
}), "decorateDefaultCredentialProvider");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 3405:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.getRuntimeConfig = void 0;
const tslib_1 = __nccwpck_require__(4351);
const package_json_1 = tslib_1.__importDefault(__nccwpck_require__(7947));
const core_1 = __nccwpck_require__(9963);
const credential_provider_node_1 = __nccwpck_require__(5531);
const util_user_agent_node_1 = __nccwpck_require__(8095);
const config_resolver_1 = __nccwpck_require__(3098);
const core_2 = __nccwpck_require__(5829);
const hash_node_1 = __nccwpck_require__(3081);
const middleware_retry_1 = __nccwpck_require__(6039);
const node_config_provider_1 = __nccwpck_require__(3461);
const node_http_handler_1 = __nccwpck_require__(258);
const util_body_length_node_1 = __nccwpck_require__(8075);
const util_retry_1 = __nccwpck_require__(4902);
const runtimeConfig_shared_1 = __nccwpck_require__(2642);
const smithy_client_1 = __nccwpck_require__(3570);
const util_defaults_mode_node_1 = __nccwpck_require__(2429);
const smithy_client_2 = __nccwpck_require__(3570);
const getRuntimeConfig = (config) => {
    (0, smithy_client_2.emitWarningIfUnsupportedVersion)(process.version);
    const defaultsMode = (0, util_defaults_mode_node_1.resolveDefaultsModeConfig)(config);
    const defaultConfigProvider = () => defaultsMode().then(smithy_client_1.loadConfigsForDefaultMode);
    const clientSharedValues = (0, runtimeConfig_shared_1.getRuntimeConfig)(config);
    (0, core_1.emitWarningIfUnsupportedVersion)(process.version);
    return {
        ...clientSharedValues,
        ...config,
        runtime: "node",
        defaultsMode,
        bodyLengthChecker: config?.bodyLengthChecker ?? util_body_length_node_1.calculateBodyLength,
        credentialDefaultProvider: config?.credentialDefaultProvider ?? credential_provider_node_1.defaultProvider,
        defaultUserAgentProvider: config?.defaultUserAgentProvider ??
            (0, util_user_agent_node_1.defaultUserAgent)({ serviceId: clientSharedValues.serviceId, clientVersion: package_json_1.default.version }),
        httpAuthSchemes: config?.httpAuthSchemes ?? [
            {
                schemeId: "aws.auth#sigv4",
                identityProvider: (ipc) => ipc.getIdentityProvider("aws.auth#sigv4") ||
                    (async (idProps) => await (0, credential_provider_node_1.defaultProvider)(idProps?.__config || {})()),
                signer: new core_1.AwsSdkSigV4Signer(),
            },
            {
                schemeId: "smithy.api#noAuth",
                identityProvider: (ipc) => ipc.getIdentityProvider("smithy.api#noAuth") || (async () => ({})),
                signer: new core_2.NoAuthSigner(),
            },
        ],
        maxAttempts: config?.maxAttempts ?? (0, node_config_provider_1.loadConfig)(middleware_retry_1.NODE_MAX_ATTEMPT_CONFIG_OPTIONS),
        region: config?.region ?? (0, node_config_provider_1.loadConfig)(config_resolver_1.NODE_REGION_CONFIG_OPTIONS, config_resolver_1.NODE_REGION_CONFIG_FILE_OPTIONS),
        requestHandler: node_http_handler_1.NodeHttpHandler.create(config?.requestHandler ?? defaultConfigProvider),
        retryMode: config?.retryMode ??
            (0, node_config_provider_1.loadConfig)({
                ...middleware_retry_1.NODE_RETRY_MODE_CONFIG_OPTIONS,
                default: async () => (await defaultConfigProvider()).retryMode || util_retry_1.DEFAULT_RETRY_MODE,
            }),
        sha256: config?.sha256 ?? hash_node_1.Hash.bind(null, "sha256"),
        streamCollector: config?.streamCollector ?? node_http_handler_1.streamCollector,
        useDualstackEndpoint: config?.useDualstackEndpoint ?? (0, node_config_provider_1.loadConfig)(config_resolver_1.NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS),
        useFipsEndpoint: config?.useFipsEndpoint ?? (0, node_config_provider_1.loadConfig)(config_resolver_1.NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS),
    };
};
exports.getRuntimeConfig = getRuntimeConfig;


/***/ }),

/***/ 2642:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.getRuntimeConfig = void 0;
const core_1 = __nccwpck_require__(9963);
const core_2 = __nccwpck_require__(5829);
const smithy_client_1 = __nccwpck_require__(3570);
const url_parser_1 = __nccwpck_require__(4681);
const util_base64_1 = __nccwpck_require__(5600);
const util_utf8_1 = __nccwpck_require__(1895);
const httpAuthSchemeProvider_1 = __nccwpck_require__(7145);
const endpointResolver_1 = __nccwpck_require__(1203);
const getRuntimeConfig = (config) => {
    return {
        apiVersion: "2011-06-15",
        base64Decoder: config?.base64Decoder ?? util_base64_1.fromBase64,
        base64Encoder: config?.base64Encoder ?? util_base64_1.toBase64,
        disableHostPrefix: config?.disableHostPrefix ?? false,
        endpointProvider: config?.endpointProvider ?? endpointResolver_1.defaultEndpointResolver,
        extensions: config?.extensions ?? [],
        httpAuthSchemeProvider: config?.httpAuthSchemeProvider ?? httpAuthSchemeProvider_1.defaultSTSHttpAuthSchemeProvider,
        httpAuthSchemes: config?.httpAuthSchemes ?? [
            {
                schemeId: "aws.auth#sigv4",
                identityProvider: (ipc) => ipc.getIdentityProvider("aws.auth#sigv4"),
                signer: new core_1.AwsSdkSigV4Signer(),
            },
            {
                schemeId: "smithy.api#noAuth",
                identityProvider: (ipc) => ipc.getIdentityProvider("smithy.api#noAuth") || (async () => ({})),
                signer: new core_2.NoAuthSigner(),
            },
        ],
        logger: config?.logger ?? new smithy_client_1.NoOpLogger(),
        serviceId: config?.serviceId ?? "STS",
        urlParser: config?.urlParser ?? url_parser_1.parseUrl,
        utf8Decoder: config?.utf8Decoder ?? util_utf8_1.fromUtf8,
        utf8Encoder: config?.utf8Encoder ?? util_utf8_1.toUtf8,
    };
};
exports.getRuntimeConfig = getRuntimeConfig;


/***/ }),

/***/ 2053:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.resolveRuntimeExtensions = void 0;
const region_config_resolver_1 = __nccwpck_require__(8156);
const protocol_http_1 = __nccwpck_require__(4418);
const smithy_client_1 = __nccwpck_require__(3570);
const httpAuthExtensionConfiguration_1 = __nccwpck_require__(8527);
const asPartial = (t) => t;
const resolveRuntimeExtensions = (runtimeConfig, extensions) => {
    const extensionConfiguration = {
        ...asPartial((0, region_config_resolver_1.getAwsRegionExtensionConfiguration)(runtimeConfig)),
        ...asPartial((0, smithy_client_1.getDefaultExtensionConfiguration)(runtimeConfig)),
        ...asPartial((0, protocol_http_1.getHttpHandlerExtensionConfiguration)(runtimeConfig)),
        ...asPartial((0, httpAuthExtensionConfiguration_1.getHttpAuthExtensionConfiguration)(runtimeConfig)),
    };
    extensions.forEach((extension) => extension.configure(extensionConfiguration));
    return {
        ...runtimeConfig,
        ...(0, region_config_resolver_1.resolveAwsRegionExtensionConfiguration)(extensionConfiguration),
        ...(0, smithy_client_1.resolveDefaultRuntimeConfig)(extensionConfiguration),
        ...(0, protocol_http_1.resolveHttpHandlerRuntimeConfig)(extensionConfiguration),
        ...(0, httpAuthExtensionConfiguration_1.resolveHttpAuthRuntimeConfig)(extensionConfiguration),
    };
};
exports.resolveRuntimeExtensions = resolveRuntimeExtensions;


/***/ }),

/***/ 9963:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
const tslib_1 = __nccwpck_require__(4351);
tslib_1.__exportStar(__nccwpck_require__(2825), exports);
tslib_1.__exportStar(__nccwpck_require__(7862), exports);
tslib_1.__exportStar(__nccwpck_require__(785), exports);


/***/ }),

/***/ 2825:
/***/ ((module) => {

"use strict";

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/submodules/client/index.ts
var client_exports = {};
__export(client_exports, {
  emitWarningIfUnsupportedVersion: () => emitWarningIfUnsupportedVersion
});
module.exports = __toCommonJS(client_exports);

// src/submodules/client/emitWarningIfUnsupportedVersion.ts
var warningEmitted = false;
var emitWarningIfUnsupportedVersion = /* @__PURE__ */ __name((version) => {
  if (version && !warningEmitted && parseInt(version.substring(1, version.indexOf("."))) < 18) {
    warningEmitted = true;
    process.emitWarning(
      `NodeDeprecationWarning: The AWS SDK for JavaScript (v3) will
no longer support Node.js 16.x on January 6, 2025.

To continue receiving updates to AWS services, bug fixes, and security
updates please upgrade to a supported Node.js LTS version.

More information can be found at: https://a.co/74kJMmI`
    );
  }
}, "emitWarningIfUnsupportedVersion");
// Annotate the CommonJS export names for ESM import in node:
0 && (0);


/***/ }),

/***/ 7862:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/submodules/httpAuthSchemes/index.ts
var httpAuthSchemes_exports = {};
__export(httpAuthSchemes_exports, {
  AWSSDKSigV4Signer: () => AWSSDKSigV4Signer,
  AwsSdkSigV4ASigner: () => AwsSdkSigV4ASigner,
  AwsSdkSigV4Signer: () => AwsSdkSigV4Signer,
  resolveAWSSDKSigV4Config: () => resolveAWSSDKSigV4Config,
  resolveAwsSdkSigV4Config: () => resolveAwsSdkSigV4Config
});
module.exports = __toCommonJS(httpAuthSchemes_exports);

// src/submodules/httpAuthSchemes/aws_sdk/AwsSdkSigV4Signer.ts
var import_protocol_http2 = __nccwpck_require__(4418);

// src/submodules/httpAuthSchemes/utils/getDateHeader.ts
var import_protocol_http = __nccwpck_require__(4418);
var getDateHeader = /* @__PURE__ */ __name((response) => {
  var _a, _b;
  return import_protocol_http.HttpResponse.isInstance(response) ? ((_a = response.headers) == null ? void 0 : _a.date) ?? ((_b = response.headers) == null ? void 0 : _b.Date) : void 0;
}, "getDateHeader");

// src/submodules/httpAuthSchemes/utils/getSkewCorrectedDate.ts
var getSkewCorrectedDate = /* @__PURE__ */ __name((systemClockOffset) => new Date(Date.now() + systemClockOffset), "getSkewCorrectedDate");

// src/submodules/httpAuthSchemes/utils/isClockSkewed.ts
var isClockSkewed = /* @__PURE__ */ __name((clockTime, systemClockOffset) => Math.abs(getSkewCorrectedDate(systemClockOffset).getTime() - clockTime) >= 3e5, "isClockSkewed");

// src/submodules/httpAuthSchemes/utils/getUpdatedSystemClockOffset.ts
var getUpdatedSystemClockOffset = /* @__PURE__ */ __name((clockTime, currentSystemClockOffset) => {
  const clockTimeInMs = Date.parse(clockTime);
  if (isClockSkewed(clockTimeInMs, currentSystemClockOffset)) {
    return clockTimeInMs - Date.now();
  }
  return currentSystemClockOffset;
}, "getUpdatedSystemClockOffset");

// src/submodules/httpAuthSchemes/aws_sdk/AwsSdkSigV4Signer.ts
var throwSigningPropertyError = /* @__PURE__ */ __name((name, property) => {
  if (!property) {
    throw new Error(`Property \`${name}\` is not resolved for AWS SDK SigV4Auth`);
  }
  return property;
}, "throwSigningPropertyError");
var validateSigningProperties = /* @__PURE__ */ __name(async (signingProperties) => {
  var _a, _b, _c;
  const context = throwSigningPropertyError(
    "context",
    signingProperties.context
  );
  const config = throwSigningPropertyError("config", signingProperties.config);
  const authScheme = (_c = (_b = (_a = context.endpointV2) == null ? void 0 : _a.properties) == null ? void 0 : _b.authSchemes) == null ? void 0 : _c[0];
  const signerFunction = throwSigningPropertyError(
    "signer",
    config.signer
  );
  const signer = await signerFunction(authScheme);
  const signingRegion = signingProperties == null ? void 0 : signingProperties.signingRegion;
  const signingRegionSet = signingProperties == null ? void 0 : signingProperties.signingRegionSet;
  const signingName = signingProperties == null ? void 0 : signingProperties.signingName;
  return {
    config,
    signer,
    signingRegion,
    signingRegionSet,
    signingName
  };
}, "validateSigningProperties");
var _AwsSdkSigV4Signer = class _AwsSdkSigV4Signer {
  async sign(httpRequest, identity, signingProperties) {
    if (!import_protocol_http2.HttpRequest.isInstance(httpRequest)) {
      throw new Error("The request is not an instance of `HttpRequest` and cannot be signed");
    }
    const { config, signer, signingRegion, signingName } = await validateSigningProperties(signingProperties);
    const signedRequest = await signer.sign(httpRequest, {
      signingDate: getSkewCorrectedDate(config.systemClockOffset),
      signingRegion,
      signingService: signingName
    });
    return signedRequest;
  }
  errorHandler(signingProperties) {
    return (error) => {
      const serverTime = error.ServerTime ?? getDateHeader(error.$response);
      if (serverTime) {
        const config = throwSigningPropertyError("config", signingProperties.config);
        const initialSystemClockOffset = config.systemClockOffset;
        config.systemClockOffset = getUpdatedSystemClockOffset(serverTime, config.systemClockOffset);
        const clockSkewCorrected = config.systemClockOffset !== initialSystemClockOffset;
        if (clockSkewCorrected && error.$metadata) {
          error.$metadata.clockSkewCorrected = true;
        }
      }
      throw error;
    };
  }
  successHandler(httpResponse, signingProperties) {
    const dateHeader = getDateHeader(httpResponse);
    if (dateHeader) {
      const config = throwSigningPropertyError("config", signingProperties.config);
      config.systemClockOffset = getUpdatedSystemClockOffset(dateHeader, config.systemClockOffset);
    }
  }
};
__name(_AwsSdkSigV4Signer, "AwsSdkSigV4Signer");
var AwsSdkSigV4Signer = _AwsSdkSigV4Signer;
var AWSSDKSigV4Signer = AwsSdkSigV4Signer;

// src/submodules/httpAuthSchemes/aws_sdk/AwsSdkSigV4ASigner.ts
var import_protocol_http3 = __nccwpck_require__(4418);
var _AwsSdkSigV4ASigner = class _AwsSdkSigV4ASigner extends AwsSdkSigV4Signer {
  async sign(httpRequest, identity, signingProperties) {
    var _a;
    if (!import_protocol_http3.HttpRequest.isInstance(httpRequest)) {
      throw new Error("The request is not an instance of `HttpRequest` and cannot be signed");
    }
    const { config, signer, signingRegion, signingRegionSet, signingName } = await validateSigningProperties(
      signingProperties
    );
    const multiRegionOverride = ((_a = signingRegionSet == null ? void 0 : signingRegionSet.join) == null ? void 0 : _a.call(signingRegionSet, ",")) ?? signingRegion;
    const signedRequest = await signer.sign(httpRequest, {
      signingDate: getSkewCorrectedDate(config.systemClockOffset),
      signingRegion: multiRegionOverride,
      signingService: signingName
    });
    return signedRequest;
  }
};
__name(_AwsSdkSigV4ASigner, "AwsSdkSigV4ASigner");
var AwsSdkSigV4ASigner = _AwsSdkSigV4ASigner;

// src/submodules/httpAuthSchemes/aws_sdk/resolveAwsSdkSigV4Config.ts
var import_core = __nccwpck_require__(5829);
var import_signature_v4 = __nccwpck_require__(1528);
var resolveAwsSdkSigV4Config = /* @__PURE__ */ __name((config) => {
  let normalizedCreds;
  if (config.credentials) {
    normalizedCreds = (0, import_core.memoizeIdentityProvider)(config.credentials, import_core.isIdentityExpired, import_core.doesIdentityRequireRefresh);
  }
  if (!normalizedCreds) {
    if (config.credentialDefaultProvider) {
      normalizedCreds = (0, import_core.normalizeProvider)(
        config.credentialDefaultProvider(
          Object.assign({}, config, {
            parentClientConfig: config
          })
        )
      );
    } else {
      normalizedCreds = /* @__PURE__ */ __name(async () => {
        throw new Error("`credentials` is missing");
      }, "normalizedCreds");
    }
  }
  const {
    // Default for signingEscapePath
    signingEscapePath = true,
    // Default for systemClockOffset
    systemClockOffset = config.systemClockOffset || 0,
    // No default for sha256 since it is platform dependent
    sha256
  } = config;
  let signer;
  if (config.signer) {
    signer = (0, import_core.normalizeProvider)(config.signer);
  } else if (config.regionInfoProvider) {
    signer = /* @__PURE__ */ __name(() => (0, import_core.normalizeProvider)(config.region)().then(
      async (region) => [
        await config.regionInfoProvider(region, {
          useFipsEndpoint: await config.useFipsEndpoint(),
          useDualstackEndpoint: await config.useDualstackEndpoint()
        }) || {},
        region
      ]
    ).then(([regionInfo, region]) => {
      const { signingRegion, signingService } = regionInfo;
      config.signingRegion = config.signingRegion || signingRegion || region;
      config.signingName = config.signingName || signingService || config.serviceId;
      const params = {
        ...config,
        credentials: normalizedCreds,
        region: config.signingRegion,
        service: config.signingName,
        sha256,
        uriEscapePath: signingEscapePath
      };
      const SignerCtor = config.signerConstructor || import_signature_v4.SignatureV4;
      return new SignerCtor(params);
    }), "signer");
  } else {
    signer = /* @__PURE__ */ __name(async (authScheme) => {
      authScheme = Object.assign(
        {},
        {
          name: "sigv4",
          signingName: config.signingName || config.defaultSigningName,
          signingRegion: await (0, import_core.normalizeProvider)(config.region)(),
          properties: {}
        },
        authScheme
      );
      const signingRegion = authScheme.signingRegion;
      const signingService = authScheme.signingName;
      config.signingRegion = config.signingRegion || signingRegion;
      config.signingName = config.signingName || signingService || config.serviceId;
      const params = {
        ...config,
        credentials: normalizedCreds,
        region: config.signingRegion,
        service: config.signingName,
        sha256,
        uriEscapePath: signingEscapePath
      };
      const SignerCtor = config.signerConstructor || import_signature_v4.SignatureV4;
      return new SignerCtor(params);
    }, "signer");
  }
  return {
    ...config,
    systemClockOffset,
    signingEscapePath,
    credentials: normalizedCreds,
    signer
  };
}, "resolveAwsSdkSigV4Config");
var resolveAWSSDKSigV4Config = resolveAwsSdkSigV4Config;
// Annotate the CommonJS export names for ESM import in node:
0 && (0);


/***/ }),

/***/ 785:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/submodules/protocols/index.ts
var protocols_exports = {};
__export(protocols_exports, {
  _toBool: () => _toBool,
  _toNum: () => _toNum,
  _toStr: () => _toStr,
  awsExpectUnion: () => awsExpectUnion,
  loadRestJsonErrorCode: () => loadRestJsonErrorCode,
  loadRestXmlErrorCode: () => loadRestXmlErrorCode,
  parseJsonBody: () => parseJsonBody,
  parseJsonErrorBody: () => parseJsonErrorBody,
  parseXmlBody: () => parseXmlBody,
  parseXmlErrorBody: () => parseXmlErrorBody
});
module.exports = __toCommonJS(protocols_exports);

// src/submodules/protocols/coercing-serializers.ts
var _toStr = /* @__PURE__ */ __name((val) => {
  if (val == null) {
    return val;
  }
  if (typeof val === "number" || typeof val === "bigint") {
    const warning = new Error(`Received number ${val} where a string was expected.`);
    warning.name = "Warning";
    console.warn(warning);
    return String(val);
  }
  if (typeof val === "boolean") {
    const warning = new Error(`Received boolean ${val} where a string was expected.`);
    warning.name = "Warning";
    console.warn(warning);
    return String(val);
  }
  return val;
}, "_toStr");
var _toBool = /* @__PURE__ */ __name((val) => {
  if (val == null) {
    return val;
  }
  if (typeof val === "number") {
  }
  if (typeof val === "string") {
    const lowercase = val.toLowerCase();
    if (val !== "" && lowercase !== "false" && lowercase !== "true") {
      const warning = new Error(`Received string "${val}" where a boolean was expected.`);
      warning.name = "Warning";
      console.warn(warning);
    }
    return val !== "" && lowercase !== "false";
  }
  return val;
}, "_toBool");
var _toNum = /* @__PURE__ */ __name((val) => {
  if (val == null) {
    return val;
  }
  if (typeof val === "boolean") {
  }
  if (typeof val === "string") {
    const num = Number(val);
    if (num.toString() !== val) {
      const warning = new Error(`Received string "${val}" where a number was expected.`);
      warning.name = "Warning";
      console.warn(warning);
      return val;
    }
    return num;
  }
  return val;
}, "_toNum");

// src/submodules/protocols/json/awsExpectUnion.ts
var import_smithy_client = __nccwpck_require__(3570);
var awsExpectUnion = /* @__PURE__ */ __name((value) => {
  if (value == null) {
    return void 0;
  }
  if (typeof value === "object" && "__type" in value) {
    delete value.__type;
  }
  return (0, import_smithy_client.expectUnion)(value);
}, "awsExpectUnion");

// src/submodules/protocols/common.ts
var import_smithy_client2 = __nccwpck_require__(3570);
var collectBodyString = /* @__PURE__ */ __name((streamBody, context) => (0, import_smithy_client2.collectBody)(streamBody, context).then((body) => context.utf8Encoder(body)), "collectBodyString");

// src/submodules/protocols/json/parseJsonBody.ts
var parseJsonBody = /* @__PURE__ */ __name((streamBody, context) => collectBodyString(streamBody, context).then((encoded) => {
  if (encoded.length) {
    try {
      return JSON.parse(encoded);
    } catch (e) {
      if ((e == null ? void 0 : e.name) === "SyntaxError") {
        Object.defineProperty(e, "$responseBodyText", {
          value: encoded
        });
      }
      throw e;
    }
  }
  return {};
}), "parseJsonBody");
var parseJsonErrorBody = /* @__PURE__ */ __name(async (errorBody, context) => {
  const value = await parseJsonBody(errorBody, context);
  value.message = value.message ?? value.Message;
  return value;
}, "parseJsonErrorBody");
var loadRestJsonErrorCode = /* @__PURE__ */ __name((output, data) => {
  const findKey = /* @__PURE__ */ __name((object, key) => Object.keys(object).find((k) => k.toLowerCase() === key.toLowerCase()), "findKey");
  const sanitizeErrorCode = /* @__PURE__ */ __name((rawValue) => {
    let cleanValue = rawValue;
    if (typeof cleanValue === "number") {
      cleanValue = cleanValue.toString();
    }
    if (cleanValue.indexOf(",") >= 0) {
      cleanValue = cleanValue.split(",")[0];
    }
    if (cleanValue.indexOf(":") >= 0) {
      cleanValue = cleanValue.split(":")[0];
    }
    if (cleanValue.indexOf("#") >= 0) {
      cleanValue = cleanValue.split("#")[1];
    }
    return cleanValue;
  }, "sanitizeErrorCode");
  const headerKey = findKey(output.headers, "x-amzn-errortype");
  if (headerKey !== void 0) {
    return sanitizeErrorCode(output.headers[headerKey]);
  }
  if (data.code !== void 0) {
    return sanitizeErrorCode(data.code);
  }
  if (data["__type"] !== void 0) {
    return sanitizeErrorCode(data["__type"]);
  }
}, "loadRestJsonErrorCode");

// src/submodules/protocols/xml/parseXmlBody.ts
var import_smithy_client3 = __nccwpck_require__(3570);
var import_fast_xml_parser = __nccwpck_require__(2603);
var parseXmlBody = /* @__PURE__ */ __name((streamBody, context) => collectBodyString(streamBody, context).then((encoded) => {
  if (encoded.length) {
    const parser = new import_fast_xml_parser.XMLParser({
      attributeNamePrefix: "",
      htmlEntities: true,
      ignoreAttributes: false,
      ignoreDeclaration: true,
      parseTagValue: false,
      trimValues: false,
      tagValueProcessor: (_, val) => val.trim() === "" && val.includes("\n") ? "" : void 0
    });
    parser.addEntity("#xD", "\r");
    parser.addEntity("#10", "\n");
    let parsedObj;
    try {
      parsedObj = parser.parse(encoded, true);
    } catch (e) {
      if (e && typeof e === "object") {
        Object.defineProperty(e, "$responseBodyText", {
          value: encoded
        });
      }
      throw e;
    }
    const textNodeName = "#text";
    const key = Object.keys(parsedObj)[0];
    const parsedObjToReturn = parsedObj[key];
    if (parsedObjToReturn[textNodeName]) {
      parsedObjToReturn[key] = parsedObjToReturn[textNodeName];
      delete parsedObjToReturn[textNodeName];
    }
    return (0, import_smithy_client3.getValueFromTextNode)(parsedObjToReturn);
  }
  return {};
}), "parseXmlBody");
var parseXmlErrorBody = /* @__PURE__ */ __name(async (errorBody, context) => {
  const value = await parseXmlBody(errorBody, context);
  if (value.Error) {
    value.Error.message = value.Error.message ?? value.Error.Message;
  }
  return value;
}, "parseXmlErrorBody");
var loadRestXmlErrorCode = /* @__PURE__ */ __name((output, data) => {
  var _a;
  if (((_a = data == null ? void 0 : data.Error) == null ? void 0 : _a.Code) !== void 0) {
    return data.Error.Code;
  }
  if ((data == null ? void 0 : data.Code) !== void 0) {
    return data.Code;
  }
  if (output.statusCode == 404) {
    return "NotFound";
  }
}, "loadRestXmlErrorCode");
// Annotate the CommonJS export names for ESM import in node:
0 && (0);


/***/ }),

/***/ 5972:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  ENV_ACCOUNT_ID: () => ENV_ACCOUNT_ID,
  ENV_CREDENTIAL_SCOPE: () => ENV_CREDENTIAL_SCOPE,
  ENV_EXPIRATION: () => ENV_EXPIRATION,
  ENV_KEY: () => ENV_KEY,
  ENV_SECRET: () => ENV_SECRET,
  ENV_SESSION: () => ENV_SESSION,
  fromEnv: () => fromEnv
});
module.exports = __toCommonJS(src_exports);

// src/fromEnv.ts
var import_property_provider = __nccwpck_require__(9721);
var ENV_KEY = "AWS_ACCESS_KEY_ID";
var ENV_SECRET = "AWS_SECRET_ACCESS_KEY";
var ENV_SESSION = "AWS_SESSION_TOKEN";
var ENV_EXPIRATION = "AWS_CREDENTIAL_EXPIRATION";
var ENV_CREDENTIAL_SCOPE = "AWS_CREDENTIAL_SCOPE";
var ENV_ACCOUNT_ID = "AWS_ACCOUNT_ID";
var fromEnv = /* @__PURE__ */ __name((init) => async () => {
  var _a;
  (_a = init == null ? void 0 : init.logger) == null ? void 0 : _a.debug("@aws-sdk/credential-provider-env - fromEnv");
  const accessKeyId = process.env[ENV_KEY];
  const secretAccessKey = process.env[ENV_SECRET];
  const sessionToken = process.env[ENV_SESSION];
  const expiry = process.env[ENV_EXPIRATION];
  const credentialScope = process.env[ENV_CREDENTIAL_SCOPE];
  const accountId = process.env[ENV_ACCOUNT_ID];
  if (accessKeyId && secretAccessKey) {
    return {
      accessKeyId,
      secretAccessKey,
      ...sessionToken && { sessionToken },
      ...expiry && { expiration: new Date(expiry) },
      ...credentialScope && { credentialScope },
      ...accountId && { accountId }
    };
  }
  throw new import_property_provider.CredentialsProviderError("Unable to find environment variable credentials.", { logger: init == null ? void 0 : init.logger });
}, "fromEnv");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 3757:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.checkUrl = void 0;
const property_provider_1 = __nccwpck_require__(9721);
const LOOPBACK_CIDR_IPv4 = "127.0.0.0/8";
const LOOPBACK_CIDR_IPv6 = "::1/128";
const ECS_CONTAINER_HOST = "169.254.170.2";
const EKS_CONTAINER_HOST_IPv4 = "169.254.170.23";
const EKS_CONTAINER_HOST_IPv6 = "[fd00:ec2::23]";
const checkUrl = (url, logger) => {
    if (url.protocol === "https:") {
        return;
    }
    if (url.hostname === ECS_CONTAINER_HOST ||
        url.hostname === EKS_CONTAINER_HOST_IPv4 ||
        url.hostname === EKS_CONTAINER_HOST_IPv6) {
        return;
    }
    if (url.hostname.includes("[")) {
        if (url.hostname === "[::1]" || url.hostname === "[0000:0000:0000:0000:0000:0000:0000:0001]") {
            return;
        }
    }
    else {
        if (url.hostname === "localhost") {
            return;
        }
        const ipComponents = url.hostname.split(".");
        const inRange = (component) => {
            const num = parseInt(component, 10);
            return 0 <= num && num <= 255;
        };
        if (ipComponents[0] === "127" &&
            inRange(ipComponents[1]) &&
            inRange(ipComponents[2]) &&
            inRange(ipComponents[3]) &&
            ipComponents.length === 4) {
            return;
        }
    }
    throw new property_provider_1.CredentialsProviderError(`URL not accepted. It must either be HTTPS or match one of the following:
  - loopback CIDR 127.0.0.0/8 or [::1/128]
  - ECS container host 169.254.170.2
  - EKS container host 169.254.170.23 or [fd00:ec2::23]`, { logger });
};
exports.checkUrl = checkUrl;


/***/ }),

/***/ 6070:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.fromHttp = void 0;
const tslib_1 = __nccwpck_require__(4351);
const node_http_handler_1 = __nccwpck_require__(258);
const property_provider_1 = __nccwpck_require__(9721);
const promises_1 = tslib_1.__importDefault(__nccwpck_require__(3292));
const checkUrl_1 = __nccwpck_require__(3757);
const requestHelpers_1 = __nccwpck_require__(9287);
const retry_wrapper_1 = __nccwpck_require__(9921);
const AWS_CONTAINER_CREDENTIALS_RELATIVE_URI = "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI";
const DEFAULT_LINK_LOCAL_HOST = "http://169.254.170.2";
const AWS_CONTAINER_CREDENTIALS_FULL_URI = "AWS_CONTAINER_CREDENTIALS_FULL_URI";
const AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE = "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE";
const AWS_CONTAINER_AUTHORIZATION_TOKEN = "AWS_CONTAINER_AUTHORIZATION_TOKEN";
const fromHttp = (options = {}) => {
    options.logger?.debug("@aws-sdk/credential-provider-http - fromHttp");
    let host;
    const relative = options.awsContainerCredentialsRelativeUri ?? process.env[AWS_CONTAINER_CREDENTIALS_RELATIVE_URI];
    const full = options.awsContainerCredentialsFullUri ?? process.env[AWS_CONTAINER_CREDENTIALS_FULL_URI];
    const token = options.awsContainerAuthorizationToken ?? process.env[AWS_CONTAINER_AUTHORIZATION_TOKEN];
    const tokenFile = options.awsContainerAuthorizationTokenFile ?? process.env[AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE];
    const warn = options.logger?.constructor?.name === "NoOpLogger" || !options.logger ? console.warn : options.logger.warn;
    if (relative && full) {
        warn("@aws-sdk/credential-provider-http: " +
            "you have set both awsContainerCredentialsRelativeUri and awsContainerCredentialsFullUri.");
        warn("awsContainerCredentialsFullUri will take precedence.");
    }
    if (token && tokenFile) {
        warn("@aws-sdk/credential-provider-http: " +
            "you have set both awsContainerAuthorizationToken and awsContainerAuthorizationTokenFile.");
        warn("awsContainerAuthorizationToken will take precedence.");
    }
    if (full) {
        host = full;
    }
    else if (relative) {
        host = `${DEFAULT_LINK_LOCAL_HOST}${relative}`;
    }
    else {
        throw new property_provider_1.CredentialsProviderError(`No HTTP credential provider host provided.
Set AWS_CONTAINER_CREDENTIALS_FULL_URI or AWS_CONTAINER_CREDENTIALS_RELATIVE_URI.`, { logger: options.logger });
    }
    const url = new URL(host);
    (0, checkUrl_1.checkUrl)(url, options.logger);
    const requestHandler = new node_http_handler_1.NodeHttpHandler({
        requestTimeout: options.timeout ?? 1000,
        connectionTimeout: options.timeout ?? 1000,
    });
    return (0, retry_wrapper_1.retryWrapper)(async () => {
        const request = (0, requestHelpers_1.createGetRequest)(url);
        if (token) {
            request.headers.Authorization = token;
        }
        else if (tokenFile) {
            request.headers.Authorization = (await promises_1.default.readFile(tokenFile)).toString();
        }
        try {
            const result = await requestHandler.handle(request);
            return (0, requestHelpers_1.getCredentials)(result.response);
        }
        catch (e) {
            throw new property_provider_1.CredentialsProviderError(String(e), { logger: options.logger });
        }
    }, options.maxRetries ?? 3, options.timeout ?? 1000);
};
exports.fromHttp = fromHttp;


/***/ }),

/***/ 9287:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.getCredentials = exports.createGetRequest = void 0;
const property_provider_1 = __nccwpck_require__(9721);
const protocol_http_1 = __nccwpck_require__(4418);
const smithy_client_1 = __nccwpck_require__(3570);
const util_stream_1 = __nccwpck_require__(6607);
function createGetRequest(url) {
    return new protocol_http_1.HttpRequest({
        protocol: url.protocol,
        hostname: url.hostname,
        port: Number(url.port),
        path: url.pathname,
        query: Array.from(url.searchParams.entries()).reduce((acc, [k, v]) => {
            acc[k] = v;
            return acc;
        }, {}),
        fragment: url.hash,
    });
}
exports.createGetRequest = createGetRequest;
async function getCredentials(response, logger) {
    const stream = (0, util_stream_1.sdkStreamMixin)(response.body);
    const str = await stream.transformToString();
    if (response.statusCode === 200) {
        const parsed = JSON.parse(str);
        if (typeof parsed.AccessKeyId !== "string" ||
            typeof parsed.SecretAccessKey !== "string" ||
            typeof parsed.Token !== "string" ||
            typeof parsed.Expiration !== "string") {
            throw new property_provider_1.CredentialsProviderError("HTTP credential provider response not of the required format, an object matching: " +
                "{ AccessKeyId: string, SecretAccessKey: string, Token: string, Expiration: string(rfc3339) }", { logger });
        }
        return {
            accessKeyId: parsed.AccessKeyId,
            secretAccessKey: parsed.SecretAccessKey,
            sessionToken: parsed.Token,
            expiration: (0, smithy_client_1.parseRfc3339DateTime)(parsed.Expiration),
        };
    }
    if (response.statusCode >= 400 && response.statusCode < 500) {
        let parsedBody = {};
        try {
            parsedBody = JSON.parse(str);
        }
        catch (e) { }
        throw Object.assign(new property_provider_1.CredentialsProviderError(`Server responded with status: ${response.statusCode}`, { logger }), {
            Code: parsedBody.Code,
            Message: parsedBody.Message,
        });
    }
    throw new property_provider_1.CredentialsProviderError(`Server responded with status: ${response.statusCode}`, { logger });
}
exports.getCredentials = getCredentials;


/***/ }),

/***/ 9921:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.retryWrapper = void 0;
const retryWrapper = (toRetry, maxRetries, delayMs) => {
    return async () => {
        for (let i = 0; i < maxRetries; ++i) {
            try {
                return await toRetry();
            }
            catch (e) {
                await new Promise((resolve) => setTimeout(resolve, delayMs));
            }
        }
        return await toRetry();
    };
};
exports.retryWrapper = retryWrapper;


/***/ }),

/***/ 7290:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.fromHttp = void 0;
var fromHttp_1 = __nccwpck_require__(6070);
Object.defineProperty(exports, "fromHttp", ({ enumerable: true, get: function () { return fromHttp_1.fromHttp; } }));


/***/ }),

/***/ 4203:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";

var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  fromIni: () => fromIni
});
module.exports = __toCommonJS(src_exports);

// src/fromIni.ts


// src/resolveProfileData.ts


// src/resolveAssumeRoleCredentials.ts

var import_shared_ini_file_loader = __nccwpck_require__(3507);

// src/resolveCredentialSource.ts
var import_property_provider = __nccwpck_require__(9721);
var resolveCredentialSource = /* @__PURE__ */ __name((credentialSource, profileName, logger) => {
  const sourceProvidersMap = {
    EcsContainer: async (options) => {
      const { fromHttp } = await Promise.resolve().then(() => __toESM(__nccwpck_require__(7290)));
      const { fromContainerMetadata } = await Promise.resolve().then(() => __toESM(__nccwpck_require__(7477)));
      logger == null ? void 0 : logger.debug("@aws-sdk/credential-provider-ini - credential_source is EcsContainer");
      return (0, import_property_provider.chain)(fromHttp(options ?? {}), fromContainerMetadata(options));
    },
    Ec2InstanceMetadata: async (options) => {
      logger == null ? void 0 : logger.debug("@aws-sdk/credential-provider-ini - credential_source is Ec2InstanceMetadata");
      const { fromInstanceMetadata } = await Promise.resolve().then(() => __toESM(__nccwpck_require__(7477)));
      return fromInstanceMetadata(options);
    },
    Environment: async (options) => {
      logger == null ? void 0 : logger.debug("@aws-sdk/credential-provider-ini - credential_source is Environment");
      const { fromEnv } = await Promise.resolve().then(() => __toESM(__nccwpck_require__(5972)));
      return fromEnv(options);
    }
  };
  if (credentialSource in sourceProvidersMap) {
    return sourceProvidersMap[credentialSource];
  } else {
    throw new import_property_provider.CredentialsProviderError(
      `Unsupported credential source in profile ${profileName}. Got ${credentialSource}, expected EcsContainer or Ec2InstanceMetadata or Environment.`,
      { logger }
    );
  }
}, "resolveCredentialSource");

// src/resolveAssumeRoleCredentials.ts
var isAssumeRoleProfile = /* @__PURE__ */ __name((arg, { profile = "default", logger } = {}) => {
  return Boolean(arg) && typeof arg === "object" && typeof arg.role_arn === "string" && ["undefined", "string"].indexOf(typeof arg.role_session_name) > -1 && ["undefined", "string"].indexOf(typeof arg.external_id) > -1 && ["undefined", "string"].indexOf(typeof arg.mfa_serial) > -1 && (isAssumeRoleWithSourceProfile(arg, { profile, logger }) || isCredentialSourceProfile(arg, { profile, logger }));
}, "isAssumeRoleProfile");
var isAssumeRoleWithSourceProfile = /* @__PURE__ */ __name((arg, { profile, logger }) => {
  var _a;
  const withSourceProfile = typeof arg.source_profile === "string" && typeof arg.credential_source === "undefined";
  if (withSourceProfile) {
    (_a = logger == null ? void 0 : logger.debug) == null ? void 0 : _a.call(logger, `    ${profile} isAssumeRoleWithSourceProfile source_profile=${arg.source_profile}`);
  }
  return withSourceProfile;
}, "isAssumeRoleWithSourceProfile");
var isCredentialSourceProfile = /* @__PURE__ */ __name((arg, { profile, logger }) => {
  var _a;
  const withProviderProfile = typeof arg.credential_source === "string" && typeof arg.source_profile === "undefined";
  if (withProviderProfile) {
    (_a = logger == null ? void 0 : logger.debug) == null ? void 0 : _a.call(logger, `    ${profile} isCredentialSourceProfile credential_source=${arg.credential_source}`);
  }
  return withProviderProfile;
}, "isCredentialSourceProfile");
var resolveAssumeRoleCredentials = /* @__PURE__ */ __name(async (profileName, profiles, options, visitedProfiles = {}) => {
  var _a, _b;
  (_a = options.logger) == null ? void 0 : _a.debug("@aws-sdk/credential-provider-ini - resolveAssumeRoleCredentials (STS)");
  const data = profiles[profileName];
  if (!options.roleAssumer) {
    const { getDefaultRoleAssumer } = await Promise.resolve().then(() => __toESM(__nccwpck_require__(2209)));
    options.roleAssumer = getDefaultRoleAssumer(
      {
        ...options.clientConfig,
        credentialProviderLogger: options.logger,
        parentClientConfig: options == null ? void 0 : options.parentClientConfig
      },
      options.clientPlugins
    );
  }
  const { source_profile } = data;
  if (source_profile && source_profile in visitedProfiles) {
    throw new import_property_provider.CredentialsProviderError(
      `Detected a cycle attempting to resolve credentials for profile ${(0, import_shared_ini_file_loader.getProfileName)(options)}. Profiles visited: ` + Object.keys(visitedProfiles).join(", "),
      { logger: options.logger }
    );
  }
  (_b = options.logger) == null ? void 0 : _b.debug(
    `@aws-sdk/credential-provider-ini - finding credential resolver using ${source_profile ? `source_profile=[${source_profile}]` : `profile=[${profileName}]`}`
  );
  const sourceCredsProvider = source_profile ? resolveProfileData(
    source_profile,
    {
      ...profiles,
      [source_profile]: {
        ...profiles[source_profile],
        // This assigns the role_arn of the "root" profile
        // to the credential_source profile so this recursive call knows
        // what role to assume.
        role_arn: data.role_arn ?? profiles[source_profile].role_arn
      }
    },
    options,
    {
      ...visitedProfiles,
      [source_profile]: true
    }
  ) : (await resolveCredentialSource(data.credential_source, profileName, options.logger)(options))();
  const params = {
    RoleArn: data.role_arn,
    RoleSessionName: data.role_session_name || `aws-sdk-js-${Date.now()}`,
    ExternalId: data.external_id,
    DurationSeconds: parseInt(data.duration_seconds || "3600", 10)
  };
  const { mfa_serial } = data;
  if (mfa_serial) {
    if (!options.mfaCodeProvider) {
      throw new import_property_provider.CredentialsProviderError(
        `Profile ${profileName} requires multi-factor authentication, but no MFA code callback was provided.`,
        { logger: options.logger, tryNextLink: false }
      );
    }
    params.SerialNumber = mfa_serial;
    params.TokenCode = await options.mfaCodeProvider(mfa_serial);
  }
  const sourceCreds = await sourceCredsProvider;
  return options.roleAssumer(sourceCreds, params);
}, "resolveAssumeRoleCredentials");

// src/resolveProcessCredentials.ts
var isProcessProfile = /* @__PURE__ */ __name((arg) => Boolean(arg) && typeof arg === "object" && typeof arg.credential_process === "string", "isProcessProfile");
var resolveProcessCredentials = /* @__PURE__ */ __name(async (options, profile) => Promise.resolve().then(() => __toESM(__nccwpck_require__(9969))).then(
  ({ fromProcess }) => fromProcess({
    ...options,
    profile
  })()
), "resolveProcessCredentials");

// src/resolveSsoCredentials.ts
var resolveSsoCredentials = /* @__PURE__ */ __name(async (profile, options = {}) => {
  const { fromSSO } = await Promise.resolve().then(() => __toESM(__nccwpck_require__(6414)));
  return fromSSO({
    profile,
    logger: options.logger
  })();
}, "resolveSsoCredentials");
var isSsoProfile = /* @__PURE__ */ __name((arg) => arg && (typeof arg.sso_start_url === "string" || typeof arg.sso_account_id === "string" || typeof arg.sso_session === "string" || typeof arg.sso_region === "string" || typeof arg.sso_role_name === "string"), "isSsoProfile");

// src/resolveStaticCredentials.ts
var isStaticCredsProfile = /* @__PURE__ */ __name((arg) => Boolean(arg) && typeof arg === "object" && typeof arg.aws_access_key_id === "string" && typeof arg.aws_secret_access_key === "string" && ["undefined", "string"].indexOf(typeof arg.aws_session_token) > -1 && ["undefined", "string"].indexOf(typeof arg.aws_account_id) > -1, "isStaticCredsProfile");
var resolveStaticCredentials = /* @__PURE__ */ __name((profile, options) => {
  var _a;
  (_a = options == null ? void 0 : options.logger) == null ? void 0 : _a.debug("@aws-sdk/credential-provider-ini - resolveStaticCredentials");
  return Promise.resolve({
    accessKeyId: profile.aws_access_key_id,
    secretAccessKey: profile.aws_secret_access_key,
    sessionToken: profile.aws_session_token,
    ...profile.aws_credential_scope && { credentialScope: profile.aws_credential_scope },
    ...profile.aws_account_id && { accountId: profile.aws_account_id }
  });
}, "resolveStaticCredentials");

// src/resolveWebIdentityCredentials.ts
var isWebIdentityProfile = /* @__PURE__ */ __name((arg) => Boolean(arg) && typeof arg === "object" && typeof arg.web_identity_token_file === "string" && typeof arg.role_arn === "string" && ["undefined", "string"].indexOf(typeof arg.role_session_name) > -1, "isWebIdentityProfile");
var resolveWebIdentityCredentials = /* @__PURE__ */ __name(async (profile, options) => Promise.resolve().then(() => __toESM(__nccwpck_require__(5646))).then(
  ({ fromTokenFile }) => fromTokenFile({
    webIdentityTokenFile: profile.web_identity_token_file,
    roleArn: profile.role_arn,
    roleSessionName: profile.role_session_name,
    roleAssumerWithWebIdentity: options.roleAssumerWithWebIdentity,
    logger: options.logger,
    parentClientConfig: options.parentClientConfig
  })()
), "resolveWebIdentityCredentials");

// src/resolveProfileData.ts
var resolveProfileData = /* @__PURE__ */ __name(async (profileName, profiles, options, visitedProfiles = {}) => {
  const data = profiles[profileName];
  if (Object.keys(visitedProfiles).length > 0 && isStaticCredsProfile(data)) {
    return resolveStaticCredentials(data, options);
  }
  if (isAssumeRoleProfile(data, { profile: profileName, logger: options.logger })) {
    return resolveAssumeRoleCredentials(profileName, profiles, options, visitedProfiles);
  }
  if (isStaticCredsProfile(data)) {
    return resolveStaticCredentials(data, options);
  }
  if (isWebIdentityProfile(data)) {
    return resolveWebIdentityCredentials(data, options);
  }
  if (isProcessProfile(data)) {
    return resolveProcessCredentials(options, profileName);
  }
  if (isSsoProfile(data)) {
    return await resolveSsoCredentials(profileName, options);
  }
  throw new import_property_provider.CredentialsProviderError(
    `Could not resolve credentials using profile: [${profileName}] in configuration/credentials file(s).`,
    { logger: options.logger }
  );
}, "resolveProfileData");

// src/fromIni.ts
var fromIni = /* @__PURE__ */ __name((init = {}) => async () => {
  var _a;
  (_a = init.logger) == null ? void 0 : _a.debug("@aws-sdk/credential-provider-ini - fromIni");
  const profiles = await (0, import_shared_ini_file_loader.parseKnownFiles)(init);
  return resolveProfileData((0, import_shared_ini_file_loader.getProfileName)(init), profiles, init);
}, "fromIni");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 5531:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";

var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  credentialsTreatedAsExpired: () => credentialsTreatedAsExpired,
  credentialsWillNeedRefresh: () => credentialsWillNeedRefresh,
  defaultProvider: () => defaultProvider
});
module.exports = __toCommonJS(src_exports);

// src/defaultProvider.ts
var import_credential_provider_env = __nccwpck_require__(5972);

var import_shared_ini_file_loader = __nccwpck_require__(3507);

// src/remoteProvider.ts
var import_property_provider = __nccwpck_require__(9721);
var ENV_IMDS_DISABLED = "AWS_EC2_METADATA_DISABLED";
var remoteProvider = /* @__PURE__ */ __name(async (init) => {
  var _a, _b;
  const { ENV_CMDS_FULL_URI, ENV_CMDS_RELATIVE_URI, fromContainerMetadata, fromInstanceMetadata } = await Promise.resolve().then(() => __toESM(__nccwpck_require__(7477)));
  if (process.env[ENV_CMDS_RELATIVE_URI] || process.env[ENV_CMDS_FULL_URI]) {
    (_a = init.logger) == null ? void 0 : _a.debug("@aws-sdk/credential-provider-node - remoteProvider::fromHttp/fromContainerMetadata");
    const { fromHttp } = await Promise.resolve().then(() => __toESM(__nccwpck_require__(7290)));
    return (0, import_property_provider.chain)(fromHttp(init), fromContainerMetadata(init));
  }
  if (process.env[ENV_IMDS_DISABLED]) {
    return async () => {
      throw new import_property_provider.CredentialsProviderError("EC2 Instance Metadata Service access disabled", { logger: init.logger });
    };
  }
  (_b = init.logger) == null ? void 0 : _b.debug("@aws-sdk/credential-provider-node - remoteProvider::fromInstanceMetadata");
  return fromInstanceMetadata(init);
}, "remoteProvider");

// src/defaultProvider.ts
var multipleCredentialSourceWarningEmitted = false;
var defaultProvider = /* @__PURE__ */ __name((init = {}) => (0, import_property_provider.memoize)(
  (0, import_property_provider.chain)(
    async () => {
      var _a, _b, _c, _d;
      const profile = init.profile ?? process.env[import_shared_ini_file_loader.ENV_PROFILE];
      if (profile) {
        const envStaticCredentialsAreSet = process.env[import_credential_provider_env.ENV_KEY] && process.env[import_credential_provider_env.ENV_SECRET];
        if (envStaticCredentialsAreSet) {
          if (!multipleCredentialSourceWarningEmitted) {
            const warnFn = ((_a = init.logger) == null ? void 0 : _a.warn) && ((_c = (_b = init.logger) == null ? void 0 : _b.constructor) == null ? void 0 : _c.name) !== "NoOpLogger" ? init.logger.warn : console.warn;
            warnFn(
              `@aws-sdk/credential-provider-node - defaultProvider::fromEnv WARNING:
    Multiple credential sources detected: 
    Both AWS_PROFILE and the pair AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY static credentials are set.
    This SDK will proceed with the AWS_PROFILE value.
    
    However, a future version may change this behavior to prefer the ENV static credentials.
    Please ensure that your environment only sets either the AWS_PROFILE or the
    AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY pair.
`
            );
            multipleCredentialSourceWarningEmitted = true;
          }
        }
        throw new import_property_provider.CredentialsProviderError("AWS_PROFILE is set, skipping fromEnv provider.", {
          logger: init.logger,
          tryNextLink: true
        });
      }
      (_d = init.logger) == null ? void 0 : _d.debug("@aws-sdk/credential-provider-node - defaultProvider::fromEnv");
      return (0, import_credential_provider_env.fromEnv)(init)();
    },
    async () => {
      var _a;
      (_a = init.logger) == null ? void 0 : _a.debug("@aws-sdk/credential-provider-node - defaultProvider::fromSSO");
      const { ssoStartUrl, ssoAccountId, ssoRegion, ssoRoleName, ssoSession } = init;
      if (!ssoStartUrl && !ssoAccountId && !ssoRegion && !ssoRoleName && !ssoSession) {
        throw new import_property_provider.CredentialsProviderError(
          "Skipping SSO provider in default chain (inputs do not include SSO fields).",
          { logger: init.logger }
        );
      }
      const { fromSSO } = await Promise.resolve().then(() => __toESM(__nccwpck_require__(6414)));
      return fromSSO(init)();
    },
    async () => {
      var _a;
      (_a = init.logger) == null ? void 0 : _a.debug("@aws-sdk/credential-provider-node - defaultProvider::fromIni");
      const { fromIni } = await Promise.resolve().then(() => __toESM(__nccwpck_require__(4203)));
      return fromIni(init)();
    },
    async () => {
      var _a;
      (_a = init.logger) == null ? void 0 : _a.debug("@aws-sdk/credential-provider-node - defaultProvider::fromProcess");
      const { fromProcess } = await Promise.resolve().then(() => __toESM(__nccwpck_require__(9969)));
      return fromProcess(init)();
    },
    async () => {
      var _a;
      (_a = init.logger) == null ? void 0 : _a.debug("@aws-sdk/credential-provider-node - defaultProvider::fromTokenFile");
      const { fromTokenFile } = await Promise.resolve().then(() => __toESM(__nccwpck_require__(5646)));
      return fromTokenFile(init)();
    },
    async () => {
      var _a;
      (_a = init.logger) == null ? void 0 : _a.debug("@aws-sdk/credential-provider-node - defaultProvider::remoteProvider");
      return (await remoteProvider(init))();
    },
    async () => {
      throw new import_property_provider.CredentialsProviderError("Could not load credentials from any providers", {
        tryNextLink: false,
        logger: init.logger
      });
    }
  ),
  credentialsTreatedAsExpired,
  credentialsWillNeedRefresh
), "defaultProvider");
var credentialsWillNeedRefresh = /* @__PURE__ */ __name((credentials) => (credentials == null ? void 0 : credentials.expiration) !== void 0, "credentialsWillNeedRefresh");
var credentialsTreatedAsExpired = /* @__PURE__ */ __name((credentials) => (credentials == null ? void 0 : credentials.expiration) !== void 0 && credentials.expiration.getTime() - Date.now() < 3e5, "credentialsTreatedAsExpired");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 9969:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  fromProcess: () => fromProcess
});
module.exports = __toCommonJS(src_exports);

// src/fromProcess.ts
var import_shared_ini_file_loader = __nccwpck_require__(3507);

// src/resolveProcessCredentials.ts
var import_property_provider = __nccwpck_require__(9721);
var import_child_process = __nccwpck_require__(2081);
var import_util = __nccwpck_require__(3837);

// src/getValidatedProcessCredentials.ts
var getValidatedProcessCredentials = /* @__PURE__ */ __name((profileName, data, profiles) => {
  var _a;
  if (data.Version !== 1) {
    throw Error(`Profile ${profileName} credential_process did not return Version 1.`);
  }
  if (data.AccessKeyId === void 0 || data.SecretAccessKey === void 0) {
    throw Error(`Profile ${profileName} credential_process returned invalid credentials.`);
  }
  if (data.Expiration) {
    const currentTime = /* @__PURE__ */ new Date();
    const expireTime = new Date(data.Expiration);
    if (expireTime < currentTime) {
      throw Error(`Profile ${profileName} credential_process returned expired credentials.`);
    }
  }
  let accountId = data.AccountId;
  if (!accountId && ((_a = profiles == null ? void 0 : profiles[profileName]) == null ? void 0 : _a.aws_account_id)) {
    accountId = profiles[profileName].aws_account_id;
  }
  return {
    accessKeyId: data.AccessKeyId,
    secretAccessKey: data.SecretAccessKey,
    ...data.SessionToken && { sessionToken: data.SessionToken },
    ...data.Expiration && { expiration: new Date(data.Expiration) },
    ...data.CredentialScope && { credentialScope: data.CredentialScope },
    ...accountId && { accountId }
  };
}, "getValidatedProcessCredentials");

// src/resolveProcessCredentials.ts
var resolveProcessCredentials = /* @__PURE__ */ __name(async (profileName, profiles, logger) => {
  const profile = profiles[profileName];
  if (profiles[profileName]) {
    const credentialProcess = profile["credential_process"];
    if (credentialProcess !== void 0) {
      const execPromise = (0, import_util.promisify)(import_child_process.exec);
      try {
        const { stdout } = await execPromise(credentialProcess);
        let data;
        try {
          data = JSON.parse(stdout.trim());
        } catch {
          throw Error(`Profile ${profileName} credential_process returned invalid JSON.`);
        }
        return getValidatedProcessCredentials(profileName, data, profiles);
      } catch (error) {
        throw new import_property_provider.CredentialsProviderError(error.message, { logger });
      }
    } else {
      throw new import_property_provider.CredentialsProviderError(`Profile ${profileName} did not contain credential_process.`, { logger });
    }
  } else {
    throw new import_property_provider.CredentialsProviderError(`Profile ${profileName} could not be found in shared credentials file.`, {
      logger
    });
  }
}, "resolveProcessCredentials");

// src/fromProcess.ts
var fromProcess = /* @__PURE__ */ __name((init = {}) => async () => {
  var _a;
  (_a = init.logger) == null ? void 0 : _a.debug("@aws-sdk/credential-provider-process - fromProcess");
  const profiles = await (0, import_shared_ini_file_loader.parseKnownFiles)(init);
  return resolveProcessCredentials((0, import_shared_ini_file_loader.getProfileName)(init), profiles, init.logger);
}, "fromProcess");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 6414:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/loadSso.ts
var loadSso_exports = {};
__export(loadSso_exports, {
  GetRoleCredentialsCommand: () => import_client_sso.GetRoleCredentialsCommand,
  SSOClient: () => import_client_sso.SSOClient
});
var import_client_sso;
var init_loadSso = __esm({
  "src/loadSso.ts"() {
    "use strict";
    import_client_sso = __nccwpck_require__(2666);
  }
});

// src/index.ts
var src_exports = {};
__export(src_exports, {
  fromSSO: () => fromSSO,
  isSsoProfile: () => isSsoProfile,
  validateSsoProfile: () => validateSsoProfile
});
module.exports = __toCommonJS(src_exports);

// src/fromSSO.ts



// src/isSsoProfile.ts
var isSsoProfile = /* @__PURE__ */ __name((arg) => arg && (typeof arg.sso_start_url === "string" || typeof arg.sso_account_id === "string" || typeof arg.sso_session === "string" || typeof arg.sso_region === "string" || typeof arg.sso_role_name === "string"), "isSsoProfile");

// src/resolveSSOCredentials.ts
var import_token_providers = __nccwpck_require__(2843);
var import_property_provider = __nccwpck_require__(9721);
var import_shared_ini_file_loader = __nccwpck_require__(3507);
var SHOULD_FAIL_CREDENTIAL_CHAIN = false;
var resolveSSOCredentials = /* @__PURE__ */ __name(async ({
  ssoStartUrl,
  ssoSession,
  ssoAccountId,
  ssoRegion,
  ssoRoleName,
  ssoClient,
  clientConfig,
  profile,
  logger
}) => {
  let token;
  const refreshMessage = `To refresh this SSO session run aws sso login with the corresponding profile.`;
  if (ssoSession) {
    try {
      const _token = await (0, import_token_providers.fromSso)({ profile })();
      token = {
        accessToken: _token.token,
        expiresAt: new Date(_token.expiration).toISOString()
      };
    } catch (e) {
      throw new import_property_provider.CredentialsProviderError(e.message, {
        tryNextLink: SHOULD_FAIL_CREDENTIAL_CHAIN,
        logger
      });
    }
  } else {
    try {
      token = await (0, import_shared_ini_file_loader.getSSOTokenFromFile)(ssoStartUrl);
    } catch (e) {
      throw new import_property_provider.CredentialsProviderError(`The SSO session associated with this profile is invalid. ${refreshMessage}`, {
        tryNextLink: SHOULD_FAIL_CREDENTIAL_CHAIN,
        logger
      });
    }
  }
  if (new Date(token.expiresAt).getTime() - Date.now() <= 0) {
    throw new import_property_provider.CredentialsProviderError(`The SSO session associated with this profile has expired. ${refreshMessage}`, {
      tryNextLink: SHOULD_FAIL_CREDENTIAL_CHAIN,
      logger
    });
  }
  const { accessToken } = token;
  const { SSOClient: SSOClient2, GetRoleCredentialsCommand: GetRoleCredentialsCommand2 } = await Promise.resolve().then(() => (init_loadSso(), loadSso_exports));
  const sso = ssoClient || new SSOClient2(
    Object.assign({}, clientConfig ?? {}, {
      region: (clientConfig == null ? void 0 : clientConfig.region) ?? ssoRegion
    })
  );
  let ssoResp;
  try {
    ssoResp = await sso.send(
      new GetRoleCredentialsCommand2({
        accountId: ssoAccountId,
        roleName: ssoRoleName,
        accessToken
      })
    );
  } catch (e) {
    throw new import_property_provider.CredentialsProviderError(e, {
      tryNextLink: SHOULD_FAIL_CREDENTIAL_CHAIN,
      logger
    });
  }
  const {
    roleCredentials: { accessKeyId, secretAccessKey, sessionToken, expiration, credentialScope, accountId } = {}
  } = ssoResp;
  if (!accessKeyId || !secretAccessKey || !sessionToken || !expiration) {
    throw new import_property_provider.CredentialsProviderError("SSO returns an invalid temporary credential.", {
      tryNextLink: SHOULD_FAIL_CREDENTIAL_CHAIN,
      logger
    });
  }
  return {
    accessKeyId,
    secretAccessKey,
    sessionToken,
    expiration: new Date(expiration),
    ...credentialScope && { credentialScope },
    ...accountId && { accountId }
  };
}, "resolveSSOCredentials");

// src/validateSsoProfile.ts

var validateSsoProfile = /* @__PURE__ */ __name((profile, logger) => {
  const { sso_start_url, sso_account_id, sso_region, sso_role_name } = profile;
  if (!sso_start_url || !sso_account_id || !sso_region || !sso_role_name) {
    throw new import_property_provider.CredentialsProviderError(
      `Profile is configured with invalid SSO credentials. Required parameters "sso_account_id", "sso_region", "sso_role_name", "sso_start_url". Got ${Object.keys(profile).join(
        ", "
      )}
Reference: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html`,
      { tryNextLink: false, logger }
    );
  }
  return profile;
}, "validateSsoProfile");

// src/fromSSO.ts
var fromSSO = /* @__PURE__ */ __name((init = {}) => async () => {
  var _a;
  (_a = init.logger) == null ? void 0 : _a.debug("@aws-sdk/credential-provider-sso - fromSSO");
  const { ssoStartUrl, ssoAccountId, ssoRegion, ssoRoleName, ssoSession } = init;
  const { ssoClient } = init;
  const profileName = (0, import_shared_ini_file_loader.getProfileName)(init);
  if (!ssoStartUrl && !ssoAccountId && !ssoRegion && !ssoRoleName && !ssoSession) {
    const profiles = await (0, import_shared_ini_file_loader.parseKnownFiles)(init);
    const profile = profiles[profileName];
    if (!profile) {
      throw new import_property_provider.CredentialsProviderError(`Profile ${profileName} was not found.`, { logger: init.logger });
    }
    if (!isSsoProfile(profile)) {
      throw new import_property_provider.CredentialsProviderError(`Profile ${profileName} is not configured with SSO credentials.`, {
        logger: init.logger
      });
    }
    if (profile == null ? void 0 : profile.sso_session) {
      const ssoSessions = await (0, import_shared_ini_file_loader.loadSsoSessionData)(init);
      const session = ssoSessions[profile.sso_session];
      const conflictMsg = ` configurations in profile ${profileName} and sso-session ${profile.sso_session}`;
      if (ssoRegion && ssoRegion !== session.sso_region) {
        throw new import_property_provider.CredentialsProviderError(`Conflicting SSO region` + conflictMsg, {
          tryNextLink: false,
          logger: init.logger
        });
      }
      if (ssoStartUrl && ssoStartUrl !== session.sso_start_url) {
        throw new import_property_provider.CredentialsProviderError(`Conflicting SSO start_url` + conflictMsg, {
          tryNextLink: false,
          logger: init.logger
        });
      }
      profile.sso_region = session.sso_region;
      profile.sso_start_url = session.sso_start_url;
    }
    const { sso_start_url, sso_account_id, sso_region, sso_role_name, sso_session } = validateSsoProfile(
      profile,
      init.logger
    );
    return resolveSSOCredentials({
      ssoStartUrl: sso_start_url,
      ssoSession: sso_session,
      ssoAccountId: sso_account_id,
      ssoRegion: sso_region,
      ssoRoleName: sso_role_name,
      ssoClient,
      clientConfig: init.clientConfig,
      profile: profileName
    });
  } else if (!ssoStartUrl || !ssoAccountId || !ssoRegion || !ssoRoleName) {
    throw new import_property_provider.CredentialsProviderError(
      'Incomplete configuration. The fromSSO() argument hash must include "ssoStartUrl", "ssoAccountId", "ssoRegion", "ssoRoleName"',
      { tryNextLink: false, logger: init.logger }
    );
  } else {
    return resolveSSOCredentials({
      ssoStartUrl,
      ssoSession,
      ssoAccountId,
      ssoRegion,
      ssoRoleName,
      ssoClient,
      clientConfig: init.clientConfig,
      profile: profileName
    });
  }
}, "fromSSO");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 5614:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.fromTokenFile = void 0;
const property_provider_1 = __nccwpck_require__(9721);
const fs_1 = __nccwpck_require__(7147);
const fromWebToken_1 = __nccwpck_require__(7905);
const ENV_TOKEN_FILE = "AWS_WEB_IDENTITY_TOKEN_FILE";
const ENV_ROLE_ARN = "AWS_ROLE_ARN";
const ENV_ROLE_SESSION_NAME = "AWS_ROLE_SESSION_NAME";
const fromTokenFile = (init = {}) => async () => {
    init.logger?.debug("@aws-sdk/credential-provider-web-identity - fromTokenFile");
    const webIdentityTokenFile = init?.webIdentityTokenFile ?? process.env[ENV_TOKEN_FILE];
    const roleArn = init?.roleArn ?? process.env[ENV_ROLE_ARN];
    const roleSessionName = init?.roleSessionName ?? process.env[ENV_ROLE_SESSION_NAME];
    if (!webIdentityTokenFile || !roleArn) {
        throw new property_provider_1.CredentialsProviderError("Web identity configuration not specified", {
            logger: init.logger,
        });
    }
    return (0, fromWebToken_1.fromWebToken)({
        ...init,
        webIdentityToken: (0, fs_1.readFileSync)(webIdentityTokenFile, { encoding: "ascii" }),
        roleArn,
        roleSessionName,
    })();
};
exports.fromTokenFile = fromTokenFile;


/***/ }),

/***/ 7905:
/***/ (function(__unused_webpack_module, exports, __nccwpck_require__) {

"use strict";

var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.fromWebToken = void 0;
const fromWebToken = (init) => async () => {
    init.logger?.debug("@aws-sdk/credential-provider-web-identity - fromWebToken");
    const { roleArn, roleSessionName, webIdentityToken, providerId, policyArns, policy, durationSeconds } = init;
    let { roleAssumerWithWebIdentity } = init;
    if (!roleAssumerWithWebIdentity) {
        const { getDefaultRoleAssumerWithWebIdentity } = await Promise.resolve().then(() => __importStar(__nccwpck_require__(2209)));
        roleAssumerWithWebIdentity = getDefaultRoleAssumerWithWebIdentity({
            ...init.clientConfig,
            credentialProviderLogger: init.logger,
            parentClientConfig: init.parentClientConfig,
        }, init.clientPlugins);
    }
    return roleAssumerWithWebIdentity({
        RoleArn: roleArn,
        RoleSessionName: roleSessionName ?? `aws-sdk-js-session-${Date.now()}`,
        WebIdentityToken: webIdentityToken,
        ProviderId: providerId,
        PolicyArns: policyArns,
        Policy: policy,
        DurationSeconds: durationSeconds,
    });
};
exports.fromWebToken = fromWebToken;


/***/ }),

/***/ 5646:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __reExport = (target, mod, secondTarget) => (__copyProps(target, mod, "default"), secondTarget && __copyProps(secondTarget, mod, "default"));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
module.exports = __toCommonJS(src_exports);
__reExport(src_exports, __nccwpck_require__(5614), module.exports);
__reExport(src_exports, __nccwpck_require__(7905), module.exports);
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 2545:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  getHostHeaderPlugin: () => getHostHeaderPlugin,
  hostHeaderMiddleware: () => hostHeaderMiddleware,
  hostHeaderMiddlewareOptions: () => hostHeaderMiddlewareOptions,
  resolveHostHeaderConfig: () => resolveHostHeaderConfig
});
module.exports = __toCommonJS(src_exports);
var import_protocol_http = __nccwpck_require__(4418);
function resolveHostHeaderConfig(input) {
  return input;
}
__name(resolveHostHeaderConfig, "resolveHostHeaderConfig");
var hostHeaderMiddleware = /* @__PURE__ */ __name((options) => (next) => async (args) => {
  if (!import_protocol_http.HttpRequest.isInstance(args.request))
    return next(args);
  const { request } = args;
  const { handlerProtocol = "" } = options.requestHandler.metadata || {};
  if (handlerProtocol.indexOf("h2") >= 0 && !request.headers[":authority"]) {
    delete request.headers["host"];
    request.headers[":authority"] = request.hostname + (request.port ? ":" + request.port : "");
  } else if (!request.headers["host"]) {
    let host = request.hostname;
    if (request.port != null)
      host += `:${request.port}`;
    request.headers["host"] = host;
  }
  return next(args);
}, "hostHeaderMiddleware");
var hostHeaderMiddlewareOptions = {
  name: "hostHeaderMiddleware",
  step: "build",
  priority: "low",
  tags: ["HOST"],
  override: true
};
var getHostHeaderPlugin = /* @__PURE__ */ __name((options) => ({
  applyToStack: (clientStack) => {
    clientStack.add(hostHeaderMiddleware(options), hostHeaderMiddlewareOptions);
  }
}), "getHostHeaderPlugin");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 14:
/***/ ((module) => {

"use strict";

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  getLoggerPlugin: () => getLoggerPlugin,
  loggerMiddleware: () => loggerMiddleware,
  loggerMiddlewareOptions: () => loggerMiddlewareOptions
});
module.exports = __toCommonJS(src_exports);

// src/loggerMiddleware.ts
var loggerMiddleware = /* @__PURE__ */ __name(() => (next, context) => async (args) => {
  var _a, _b;
  try {
    const response = await next(args);
    const { clientName, commandName, logger, dynamoDbDocumentClientOptions = {} } = context;
    const { overrideInputFilterSensitiveLog, overrideOutputFilterSensitiveLog } = dynamoDbDocumentClientOptions;
    const inputFilterSensitiveLog = overrideInputFilterSensitiveLog ?? context.inputFilterSensitiveLog;
    const outputFilterSensitiveLog = overrideOutputFilterSensitiveLog ?? context.outputFilterSensitiveLog;
    const { $metadata, ...outputWithoutMetadata } = response.output;
    (_a = logger == null ? void 0 : logger.info) == null ? void 0 : _a.call(logger, {
      clientName,
      commandName,
      input: inputFilterSensitiveLog(args.input),
      output: outputFilterSensitiveLog(outputWithoutMetadata),
      metadata: $metadata
    });
    return response;
  } catch (error) {
    const { clientName, commandName, logger, dynamoDbDocumentClientOptions = {} } = context;
    const { overrideInputFilterSensitiveLog } = dynamoDbDocumentClientOptions;
    const inputFilterSensitiveLog = overrideInputFilterSensitiveLog ?? context.inputFilterSensitiveLog;
    (_b = logger == null ? void 0 : logger.error) == null ? void 0 : _b.call(logger, {
      clientName,
      commandName,
      input: inputFilterSensitiveLog(args.input),
      error,
      metadata: error.$metadata
    });
    throw error;
  }
}, "loggerMiddleware");
var loggerMiddlewareOptions = {
  name: "loggerMiddleware",
  tags: ["LOGGER"],
  step: "initialize",
  override: true
};
var getLoggerPlugin = /* @__PURE__ */ __name((options) => ({
  applyToStack: (clientStack) => {
    clientStack.add(loggerMiddleware(), loggerMiddlewareOptions);
  }
}), "getLoggerPlugin");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 5525:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  addRecursionDetectionMiddlewareOptions: () => addRecursionDetectionMiddlewareOptions,
  getRecursionDetectionPlugin: () => getRecursionDetectionPlugin,
  recursionDetectionMiddleware: () => recursionDetectionMiddleware
});
module.exports = __toCommonJS(src_exports);
var import_protocol_http = __nccwpck_require__(4418);
var TRACE_ID_HEADER_NAME = "X-Amzn-Trace-Id";
var ENV_LAMBDA_FUNCTION_NAME = "AWS_LAMBDA_FUNCTION_NAME";
var ENV_TRACE_ID = "_X_AMZN_TRACE_ID";
var recursionDetectionMiddleware = /* @__PURE__ */ __name((options) => (next) => async (args) => {
  const { request } = args;
  if (!import_protocol_http.HttpRequest.isInstance(request) || options.runtime !== "node" || request.headers.hasOwnProperty(TRACE_ID_HEADER_NAME)) {
    return next(args);
  }
  const functionName = process.env[ENV_LAMBDA_FUNCTION_NAME];
  const traceId = process.env[ENV_TRACE_ID];
  const nonEmptyString = /* @__PURE__ */ __name((str) => typeof str === "string" && str.length > 0, "nonEmptyString");
  if (nonEmptyString(functionName) && nonEmptyString(traceId)) {
    request.headers[TRACE_ID_HEADER_NAME] = traceId;
  }
  return next({
    ...args,
    request
  });
}, "recursionDetectionMiddleware");
var addRecursionDetectionMiddlewareOptions = {
  step: "build",
  tags: ["RECURSION_DETECTION"],
  name: "recursionDetectionMiddleware",
  override: true,
  priority: "low"
};
var getRecursionDetectionPlugin = /* @__PURE__ */ __name((options) => ({
  applyToStack: (clientStack) => {
    clientStack.add(recursionDetectionMiddleware(options), addRecursionDetectionMiddlewareOptions);
  }
}), "getRecursionDetectionPlugin");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 4688:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  getUserAgentMiddlewareOptions: () => getUserAgentMiddlewareOptions,
  getUserAgentPlugin: () => getUserAgentPlugin,
  resolveUserAgentConfig: () => resolveUserAgentConfig,
  userAgentMiddleware: () => userAgentMiddleware
});
module.exports = __toCommonJS(src_exports);

// src/configurations.ts
function resolveUserAgentConfig(input) {
  return {
    ...input,
    customUserAgent: typeof input.customUserAgent === "string" ? [[input.customUserAgent]] : input.customUserAgent
  };
}
__name(resolveUserAgentConfig, "resolveUserAgentConfig");

// src/user-agent-middleware.ts
var import_util_endpoints = __nccwpck_require__(3350);
var import_protocol_http = __nccwpck_require__(4418);

// src/constants.ts
var USER_AGENT = "user-agent";
var X_AMZ_USER_AGENT = "x-amz-user-agent";
var SPACE = " ";
var UA_NAME_SEPARATOR = "/";
var UA_NAME_ESCAPE_REGEX = /[^\!\$\%\&\'\*\+\-\.\^\_\`\|\~\d\w]/g;
var UA_VALUE_ESCAPE_REGEX = /[^\!\$\%\&\'\*\+\-\.\^\_\`\|\~\d\w\#]/g;
var UA_ESCAPE_CHAR = "-";

// src/user-agent-middleware.ts
var userAgentMiddleware = /* @__PURE__ */ __name((options) => (next, context) => async (args) => {
  var _a, _b;
  const { request } = args;
  if (!import_protocol_http.HttpRequest.isInstance(request))
    return next(args);
  const { headers } = request;
  const userAgent = ((_a = context == null ? void 0 : context.userAgent) == null ? void 0 : _a.map(escapeUserAgent)) || [];
  const defaultUserAgent = (await options.defaultUserAgentProvider()).map(escapeUserAgent);
  const customUserAgent = ((_b = options == null ? void 0 : options.customUserAgent) == null ? void 0 : _b.map(escapeUserAgent)) || [];
  const prefix = (0, import_util_endpoints.getUserAgentPrefix)();
  const sdkUserAgentValue = (prefix ? [prefix] : []).concat([...defaultUserAgent, ...userAgent, ...customUserAgent]).join(SPACE);
  const normalUAValue = [
    ...defaultUserAgent.filter((section) => section.startsWith("aws-sdk-")),
    ...customUserAgent
  ].join(SPACE);
  if (options.runtime !== "browser") {
    if (normalUAValue) {
      headers[X_AMZ_USER_AGENT] = headers[X_AMZ_USER_AGENT] ? `${headers[USER_AGENT]} ${normalUAValue}` : normalUAValue;
    }
    headers[USER_AGENT] = sdkUserAgentValue;
  } else {
    headers[X_AMZ_USER_AGENT] = sdkUserAgentValue;
  }
  return next({
    ...args,
    request
  });
}, "userAgentMiddleware");
var escapeUserAgent = /* @__PURE__ */ __name((userAgentPair) => {
  var _a;
  const name = userAgentPair[0].split(UA_NAME_SEPARATOR).map((part) => part.replace(UA_NAME_ESCAPE_REGEX, UA_ESCAPE_CHAR)).join(UA_NAME_SEPARATOR);
  const version = (_a = userAgentPair[1]) == null ? void 0 : _a.replace(UA_VALUE_ESCAPE_REGEX, UA_ESCAPE_CHAR);
  const prefixSeparatorIndex = name.indexOf(UA_NAME_SEPARATOR);
  const prefix = name.substring(0, prefixSeparatorIndex);
  let uaName = name.substring(prefixSeparatorIndex + 1);
  if (prefix === "api") {
    uaName = uaName.toLowerCase();
  }
  return [prefix, uaName, version].filter((item) => item && item.length > 0).reduce((acc, item, index) => {
    switch (index) {
      case 0:
        return item;
      case 1:
        return `${acc}/${item}`;
      default:
        return `${acc}#${item}`;
    }
  }, "");
}, "escapeUserAgent");
var getUserAgentMiddlewareOptions = {
  name: "getUserAgentMiddleware",
  step: "build",
  priority: "low",
  tags: ["SET_USER_AGENT", "USER_AGENT"],
  override: true
};
var getUserAgentPlugin = /* @__PURE__ */ __name((config) => ({
  applyToStack: (clientStack) => {
    clientStack.add(userAgentMiddleware(config), getUserAgentMiddlewareOptions);
  }
}), "getUserAgentPlugin");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 8156:
/***/ ((module) => {

"use strict";

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  NODE_REGION_CONFIG_FILE_OPTIONS: () => NODE_REGION_CONFIG_FILE_OPTIONS,
  NODE_REGION_CONFIG_OPTIONS: () => NODE_REGION_CONFIG_OPTIONS,
  REGION_ENV_NAME: () => REGION_ENV_NAME,
  REGION_INI_NAME: () => REGION_INI_NAME,
  getAwsRegionExtensionConfiguration: () => getAwsRegionExtensionConfiguration,
  resolveAwsRegionExtensionConfiguration: () => resolveAwsRegionExtensionConfiguration,
  resolveRegionConfig: () => resolveRegionConfig
});
module.exports = __toCommonJS(src_exports);

// src/extensions/index.ts
var getAwsRegionExtensionConfiguration = /* @__PURE__ */ __name((runtimeConfig) => {
  let runtimeConfigRegion = /* @__PURE__ */ __name(async () => {
    if (runtimeConfig.region === void 0) {
      throw new Error("Region is missing from runtimeConfig");
    }
    const region = runtimeConfig.region;
    if (typeof region === "string") {
      return region;
    }
    return region();
  }, "runtimeConfigRegion");
  return {
    setRegion(region) {
      runtimeConfigRegion = region;
    },
    region() {
      return runtimeConfigRegion;
    }
  };
}, "getAwsRegionExtensionConfiguration");
var resolveAwsRegionExtensionConfiguration = /* @__PURE__ */ __name((awsRegionExtensionConfiguration) => {
  return {
    region: awsRegionExtensionConfiguration.region()
  };
}, "resolveAwsRegionExtensionConfiguration");

// src/regionConfig/config.ts
var REGION_ENV_NAME = "AWS_REGION";
var REGION_INI_NAME = "region";
var NODE_REGION_CONFIG_OPTIONS = {
  environmentVariableSelector: (env) => env[REGION_ENV_NAME],
  configFileSelector: (profile) => profile[REGION_INI_NAME],
  default: () => {
    throw new Error("Region is missing");
  }
};
var NODE_REGION_CONFIG_FILE_OPTIONS = {
  preferredFile: "credentials"
};

// src/regionConfig/isFipsRegion.ts
var isFipsRegion = /* @__PURE__ */ __name((region) => typeof region === "string" && (region.startsWith("fips-") || region.endsWith("-fips")), "isFipsRegion");

// src/regionConfig/getRealRegion.ts
var getRealRegion = /* @__PURE__ */ __name((region) => isFipsRegion(region) ? ["fips-aws-global", "aws-fips"].includes(region) ? "us-east-1" : region.replace(/fips-(dkr-|prod-)?|-fips/, "") : region, "getRealRegion");

// src/regionConfig/resolveRegionConfig.ts
var resolveRegionConfig = /* @__PURE__ */ __name((input) => {
  const { region, useFipsEndpoint } = input;
  if (!region) {
    throw new Error("Region is missing");
  }
  return {
    ...input,
    region: async () => {
      if (typeof region === "string") {
        return getRealRegion(region);
      }
      const providedRegion = await region();
      return getRealRegion(providedRegion);
    },
    useFipsEndpoint: async () => {
      const providedRegion = typeof region === "string" ? region : await region();
      if (isFipsRegion(providedRegion)) {
        return true;
      }
      return typeof useFipsEndpoint !== "function" ? Promise.resolve(!!useFipsEndpoint) : useFipsEndpoint();
    }
  };
}, "resolveRegionConfig");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 2843:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";

var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  fromSso: () => fromSso,
  fromStatic: () => fromStatic,
  nodeProvider: () => nodeProvider
});
module.exports = __toCommonJS(src_exports);

// src/fromSso.ts



// src/constants.ts
var EXPIRE_WINDOW_MS = 5 * 60 * 1e3;
var REFRESH_MESSAGE = `To refresh this SSO session run 'aws sso login' with the corresponding profile.`;

// src/getSsoOidcClient.ts
var ssoOidcClientsHash = {};
var getSsoOidcClient = /* @__PURE__ */ __name(async (ssoRegion) => {
  const { SSOOIDCClient } = await Promise.resolve().then(() => __toESM(__nccwpck_require__(4527)));
  if (ssoOidcClientsHash[ssoRegion]) {
    return ssoOidcClientsHash[ssoRegion];
  }
  const ssoOidcClient = new SSOOIDCClient({ region: ssoRegion });
  ssoOidcClientsHash[ssoRegion] = ssoOidcClient;
  return ssoOidcClient;
}, "getSsoOidcClient");

// src/getNewSsoOidcToken.ts
var getNewSsoOidcToken = /* @__PURE__ */ __name(async (ssoToken, ssoRegion) => {
  const { CreateTokenCommand } = await Promise.resolve().then(() => __toESM(__nccwpck_require__(4527)));
  const ssoOidcClient = await getSsoOidcClient(ssoRegion);
  return ssoOidcClient.send(
    new CreateTokenCommand({
      clientId: ssoToken.clientId,
      clientSecret: ssoToken.clientSecret,
      refreshToken: ssoToken.refreshToken,
      grantType: "refresh_token"
    })
  );
}, "getNewSsoOidcToken");

// src/validateTokenExpiry.ts
var import_property_provider = __nccwpck_require__(9721);
var validateTokenExpiry = /* @__PURE__ */ __name((token) => {
  if (token.expiration && token.expiration.getTime() < Date.now()) {
    throw new import_property_provider.TokenProviderError(`Token is expired. ${REFRESH_MESSAGE}`, false);
  }
}, "validateTokenExpiry");

// src/validateTokenKey.ts

var validateTokenKey = /* @__PURE__ */ __name((key, value, forRefresh = false) => {
  if (typeof value === "undefined") {
    throw new import_property_provider.TokenProviderError(
      `Value not present for '${key}' in SSO Token${forRefresh ? ". Cannot refresh" : ""}. ${REFRESH_MESSAGE}`,
      false
    );
  }
}, "validateTokenKey");

// src/writeSSOTokenToFile.ts
var import_shared_ini_file_loader = __nccwpck_require__(3507);
var import_fs = __nccwpck_require__(7147);
var { writeFile } = import_fs.promises;
var writeSSOTokenToFile = /* @__PURE__ */ __name((id, ssoToken) => {
  const tokenFilepath = (0, import_shared_ini_file_loader.getSSOTokenFilepath)(id);
  const tokenString = JSON.stringify(ssoToken, null, 2);
  return writeFile(tokenFilepath, tokenString);
}, "writeSSOTokenToFile");

// src/fromSso.ts
var lastRefreshAttemptTime = /* @__PURE__ */ new Date(0);
var fromSso = /* @__PURE__ */ __name((init = {}) => async () => {
  var _a;
  (_a = init.logger) == null ? void 0 : _a.debug("@aws-sdk/token-providers - fromSso");
  const profiles = await (0, import_shared_ini_file_loader.parseKnownFiles)(init);
  const profileName = (0, import_shared_ini_file_loader.getProfileName)(init);
  const profile = profiles[profileName];
  if (!profile) {
    throw new import_property_provider.TokenProviderError(`Profile '${profileName}' could not be found in shared credentials file.`, false);
  } else if (!profile["sso_session"]) {
    throw new import_property_provider.TokenProviderError(`Profile '${profileName}' is missing required property 'sso_session'.`);
  }
  const ssoSessionName = profile["sso_session"];
  const ssoSessions = await (0, import_shared_ini_file_loader.loadSsoSessionData)(init);
  const ssoSession = ssoSessions[ssoSessionName];
  if (!ssoSession) {
    throw new import_property_provider.TokenProviderError(
      `Sso session '${ssoSessionName}' could not be found in shared credentials file.`,
      false
    );
  }
  for (const ssoSessionRequiredKey of ["sso_start_url", "sso_region"]) {
    if (!ssoSession[ssoSessionRequiredKey]) {
      throw new import_property_provider.TokenProviderError(
        `Sso session '${ssoSessionName}' is missing required property '${ssoSessionRequiredKey}'.`,
        false
      );
    }
  }
  const ssoStartUrl = ssoSession["sso_start_url"];
  const ssoRegion = ssoSession["sso_region"];
  let ssoToken;
  try {
    ssoToken = await (0, import_shared_ini_file_loader.getSSOTokenFromFile)(ssoSessionName);
  } catch (e) {
    throw new import_property_provider.TokenProviderError(
      `The SSO session token associated with profile=${profileName} was not found or is invalid. ${REFRESH_MESSAGE}`,
      false
    );
  }
  validateTokenKey("accessToken", ssoToken.accessToken);
  validateTokenKey("expiresAt", ssoToken.expiresAt);
  const { accessToken, expiresAt } = ssoToken;
  const existingToken = { token: accessToken, expiration: new Date(expiresAt) };
  if (existingToken.expiration.getTime() - Date.now() > EXPIRE_WINDOW_MS) {
    return existingToken;
  }
  if (Date.now() - lastRefreshAttemptTime.getTime() < 30 * 1e3) {
    validateTokenExpiry(existingToken);
    return existingToken;
  }
  validateTokenKey("clientId", ssoToken.clientId, true);
  validateTokenKey("clientSecret", ssoToken.clientSecret, true);
  validateTokenKey("refreshToken", ssoToken.refreshToken, true);
  try {
    lastRefreshAttemptTime.setTime(Date.now());
    const newSsoOidcToken = await getNewSsoOidcToken(ssoToken, ssoRegion);
    validateTokenKey("accessToken", newSsoOidcToken.accessToken);
    validateTokenKey("expiresIn", newSsoOidcToken.expiresIn);
    const newTokenExpiration = new Date(Date.now() + newSsoOidcToken.expiresIn * 1e3);
    try {
      await writeSSOTokenToFile(ssoSessionName, {
        ...ssoToken,
        accessToken: newSsoOidcToken.accessToken,
        expiresAt: newTokenExpiration.toISOString(),
        refreshToken: newSsoOidcToken.refreshToken
      });
    } catch (error) {
    }
    return {
      token: newSsoOidcToken.accessToken,
      expiration: newTokenExpiration
    };
  } catch (error) {
    validateTokenExpiry(existingToken);
    return existingToken;
  }
}, "fromSso");

// src/fromStatic.ts

var fromStatic = /* @__PURE__ */ __name(({ token, logger }) => async () => {
  logger == null ? void 0 : logger.debug("@aws-sdk/token-providers - fromStatic");
  if (!token || !token.token) {
    throw new import_property_provider.TokenProviderError(`Please pass a valid token to fromStatic`, false);
  }
  return token;
}, "fromStatic");

// src/nodeProvider.ts

var nodeProvider = /* @__PURE__ */ __name((init = {}) => (0, import_property_provider.memoize)(
  (0, import_property_provider.chain)(fromSso(init), async () => {
    throw new import_property_provider.TokenProviderError("Could not load token from any providers", false);
  }),
  (token) => token.expiration !== void 0 && token.expiration.getTime() - Date.now() < 3e5,
  (token) => token.expiration !== void 0
), "nodeProvider");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 3350:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  ConditionObject: () => import_util_endpoints.ConditionObject,
  DeprecatedObject: () => import_util_endpoints.DeprecatedObject,
  EndpointError: () => import_util_endpoints.EndpointError,
  EndpointObject: () => import_util_endpoints.EndpointObject,
  EndpointObjectHeaders: () => import_util_endpoints.EndpointObjectHeaders,
  EndpointObjectProperties: () => import_util_endpoints.EndpointObjectProperties,
  EndpointParams: () => import_util_endpoints.EndpointParams,
  EndpointResolverOptions: () => import_util_endpoints.EndpointResolverOptions,
  EndpointRuleObject: () => import_util_endpoints.EndpointRuleObject,
  ErrorRuleObject: () => import_util_endpoints.ErrorRuleObject,
  EvaluateOptions: () => import_util_endpoints.EvaluateOptions,
  Expression: () => import_util_endpoints.Expression,
  FunctionArgv: () => import_util_endpoints.FunctionArgv,
  FunctionObject: () => import_util_endpoints.FunctionObject,
  FunctionReturn: () => import_util_endpoints.FunctionReturn,
  ParameterObject: () => import_util_endpoints.ParameterObject,
  ReferenceObject: () => import_util_endpoints.ReferenceObject,
  ReferenceRecord: () => import_util_endpoints.ReferenceRecord,
  RuleSetObject: () => import_util_endpoints.RuleSetObject,
  RuleSetRules: () => import_util_endpoints.RuleSetRules,
  TreeRuleObject: () => import_util_endpoints.TreeRuleObject,
  awsEndpointFunctions: () => awsEndpointFunctions,
  getUserAgentPrefix: () => getUserAgentPrefix,
  isIpAddress: () => import_util_endpoints.isIpAddress,
  partition: () => partition,
  resolveEndpoint: () => import_util_endpoints.resolveEndpoint,
  setPartitionInfo: () => setPartitionInfo,
  useDefaultPartitionInfo: () => useDefaultPartitionInfo
});
module.exports = __toCommonJS(src_exports);

// src/aws.ts


// src/lib/aws/isVirtualHostableS3Bucket.ts


// src/lib/isIpAddress.ts
var import_util_endpoints = __nccwpck_require__(5473);

// src/lib/aws/isVirtualHostableS3Bucket.ts
var isVirtualHostableS3Bucket = /* @__PURE__ */ __name((value, allowSubDomains = false) => {
  if (allowSubDomains) {
    for (const label of value.split(".")) {
      if (!isVirtualHostableS3Bucket(label)) {
        return false;
      }
    }
    return true;
  }
  if (!(0, import_util_endpoints.isValidHostLabel)(value)) {
    return false;
  }
  if (value.length < 3 || value.length > 63) {
    return false;
  }
  if (value !== value.toLowerCase()) {
    return false;
  }
  if ((0, import_util_endpoints.isIpAddress)(value)) {
    return false;
  }
  return true;
}, "isVirtualHostableS3Bucket");

// src/lib/aws/parseArn.ts
var parseArn = /* @__PURE__ */ __name((value) => {
  const segments = value.split(":");
  if (segments.length < 6)
    return null;
  const [arn, partition2, service, region, accountId, ...resourceId] = segments;
  if (arn !== "arn" || partition2 === "" || service === "" || resourceId[0] === "")
    return null;
  return {
    partition: partition2,
    service,
    region,
    accountId,
    resourceId: resourceId[0].includes("/") ? resourceId[0].split("/") : resourceId
  };
}, "parseArn");

// src/lib/aws/partitions.json
var partitions_default = {
  partitions: [{
    id: "aws",
    outputs: {
      dnsSuffix: "amazonaws.com",
      dualStackDnsSuffix: "api.aws",
      implicitGlobalRegion: "us-east-1",
      name: "aws",
      supportsDualStack: true,
      supportsFIPS: true
    },
    regionRegex: "^(us|eu|ap|sa|ca|me|af|il)\\-\\w+\\-\\d+$",
    regions: {
      "af-south-1": {
        description: "Africa (Cape Town)"
      },
      "ap-east-1": {
        description: "Asia Pacific (Hong Kong)"
      },
      "ap-northeast-1": {
        description: "Asia Pacific (Tokyo)"
      },
      "ap-northeast-2": {
        description: "Asia Pacific (Seoul)"
      },
      "ap-northeast-3": {
        description: "Asia Pacific (Osaka)"
      },
      "ap-south-1": {
        description: "Asia Pacific (Mumbai)"
      },
      "ap-south-2": {
        description: "Asia Pacific (Hyderabad)"
      },
      "ap-southeast-1": {
        description: "Asia Pacific (Singapore)"
      },
      "ap-southeast-2": {
        description: "Asia Pacific (Sydney)"
      },
      "ap-southeast-3": {
        description: "Asia Pacific (Jakarta)"
      },
      "ap-southeast-4": {
        description: "Asia Pacific (Melbourne)"
      },
      "aws-global": {
        description: "AWS Standard global region"
      },
      "ca-central-1": {
        description: "Canada (Central)"
      },
      "ca-west-1": {
        description: "Canada West (Calgary)"
      },
      "eu-central-1": {
        description: "Europe (Frankfurt)"
      },
      "eu-central-2": {
        description: "Europe (Zurich)"
      },
      "eu-north-1": {
        description: "Europe (Stockholm)"
      },
      "eu-south-1": {
        description: "Europe (Milan)"
      },
      "eu-south-2": {
        description: "Europe (Spain)"
      },
      "eu-west-1": {
        description: "Europe (Ireland)"
      },
      "eu-west-2": {
        description: "Europe (London)"
      },
      "eu-west-3": {
        description: "Europe (Paris)"
      },
      "il-central-1": {
        description: "Israel (Tel Aviv)"
      },
      "me-central-1": {
        description: "Middle East (UAE)"
      },
      "me-south-1": {
        description: "Middle East (Bahrain)"
      },
      "sa-east-1": {
        description: "South America (Sao Paulo)"
      },
      "us-east-1": {
        description: "US East (N. Virginia)"
      },
      "us-east-2": {
        description: "US East (Ohio)"
      },
      "us-west-1": {
        description: "US West (N. California)"
      },
      "us-west-2": {
        description: "US West (Oregon)"
      }
    }
  }, {
    id: "aws-cn",
    outputs: {
      dnsSuffix: "amazonaws.com.cn",
      dualStackDnsSuffix: "api.amazonwebservices.com.cn",
      implicitGlobalRegion: "cn-northwest-1",
      name: "aws-cn",
      supportsDualStack: true,
      supportsFIPS: true
    },
    regionRegex: "^cn\\-\\w+\\-\\d+$",
    regions: {
      "aws-cn-global": {
        description: "AWS China global region"
      },
      "cn-north-1": {
        description: "China (Beijing)"
      },
      "cn-northwest-1": {
        description: "China (Ningxia)"
      }
    }
  }, {
    id: "aws-us-gov",
    outputs: {
      dnsSuffix: "amazonaws.com",
      dualStackDnsSuffix: "api.aws",
      implicitGlobalRegion: "us-gov-west-1",
      name: "aws-us-gov",
      supportsDualStack: true,
      supportsFIPS: true
    },
    regionRegex: "^us\\-gov\\-\\w+\\-\\d+$",
    regions: {
      "aws-us-gov-global": {
        description: "AWS GovCloud (US) global region"
      },
      "us-gov-east-1": {
        description: "AWS GovCloud (US-East)"
      },
      "us-gov-west-1": {
        description: "AWS GovCloud (US-West)"
      }
    }
  }, {
    id: "aws-iso",
    outputs: {
      dnsSuffix: "c2s.ic.gov",
      dualStackDnsSuffix: "c2s.ic.gov",
      implicitGlobalRegion: "us-iso-east-1",
      name: "aws-iso",
      supportsDualStack: false,
      supportsFIPS: true
    },
    regionRegex: "^us\\-iso\\-\\w+\\-\\d+$",
    regions: {
      "aws-iso-global": {
        description: "AWS ISO (US) global region"
      },
      "us-iso-east-1": {
        description: "US ISO East"
      },
      "us-iso-west-1": {
        description: "US ISO WEST"
      }
    }
  }, {
    id: "aws-iso-b",
    outputs: {
      dnsSuffix: "sc2s.sgov.gov",
      dualStackDnsSuffix: "sc2s.sgov.gov",
      implicitGlobalRegion: "us-isob-east-1",
      name: "aws-iso-b",
      supportsDualStack: false,
      supportsFIPS: true
    },
    regionRegex: "^us\\-isob\\-\\w+\\-\\d+$",
    regions: {
      "aws-iso-b-global": {
        description: "AWS ISOB (US) global region"
      },
      "us-isob-east-1": {
        description: "US ISOB East (Ohio)"
      }
    }
  }, {
    id: "aws-iso-e",
    outputs: {
      dnsSuffix: "cloud.adc-e.uk",
      dualStackDnsSuffix: "cloud.adc-e.uk",
      implicitGlobalRegion: "eu-isoe-west-1",
      name: "aws-iso-e",
      supportsDualStack: false,
      supportsFIPS: true
    },
    regionRegex: "^eu\\-isoe\\-\\w+\\-\\d+$",
    regions: {
      "eu-isoe-west-1": {
        description: "EU ISOE West"
      }
    }
  }, {
    id: "aws-iso-f",
    outputs: {
      dnsSuffix: "csp.hci.ic.gov",
      dualStackDnsSuffix: "csp.hci.ic.gov",
      implicitGlobalRegion: "us-isof-south-1",
      name: "aws-iso-f",
      supportsDualStack: false,
      supportsFIPS: true
    },
    regionRegex: "^us\\-isof\\-\\w+\\-\\d+$",
    regions: {}
  }],
  version: "1.1"
};

// src/lib/aws/partition.ts
var selectedPartitionsInfo = partitions_default;
var selectedUserAgentPrefix = "";
var partition = /* @__PURE__ */ __name((value) => {
  const { partitions } = selectedPartitionsInfo;
  for (const partition2 of partitions) {
    const { regions, outputs } = partition2;
    for (const [region, regionData] of Object.entries(regions)) {
      if (region === value) {
        return {
          ...outputs,
          ...regionData
        };
      }
    }
  }
  for (const partition2 of partitions) {
    const { regionRegex, outputs } = partition2;
    if (new RegExp(regionRegex).test(value)) {
      return {
        ...outputs
      };
    }
  }
  const DEFAULT_PARTITION = partitions.find((partition2) => partition2.id === "aws");
  if (!DEFAULT_PARTITION) {
    throw new Error(
      "Provided region was not found in the partition array or regex, and default partition with id 'aws' doesn't exist."
    );
  }
  return {
    ...DEFAULT_PARTITION.outputs
  };
}, "partition");
var setPartitionInfo = /* @__PURE__ */ __name((partitionsInfo, userAgentPrefix = "") => {
  selectedPartitionsInfo = partitionsInfo;
  selectedUserAgentPrefix = userAgentPrefix;
}, "setPartitionInfo");
var useDefaultPartitionInfo = /* @__PURE__ */ __name(() => {
  setPartitionInfo(partitions_default, "");
}, "useDefaultPartitionInfo");
var getUserAgentPrefix = /* @__PURE__ */ __name(() => selectedUserAgentPrefix, "getUserAgentPrefix");

// src/aws.ts
var awsEndpointFunctions = {
  isVirtualHostableS3Bucket,
  parseArn,
  partition
};
import_util_endpoints.customEndpointFunctions.aws = awsEndpointFunctions;

// src/resolveEndpoint.ts


// src/types/EndpointError.ts


// src/types/EndpointRuleObject.ts


// src/types/ErrorRuleObject.ts


// src/types/RuleSetObject.ts


// src/types/TreeRuleObject.ts


// src/types/shared.ts

// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 8095:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  UA_APP_ID_ENV_NAME: () => UA_APP_ID_ENV_NAME,
  UA_APP_ID_INI_NAME: () => UA_APP_ID_INI_NAME,
  crtAvailability: () => crtAvailability,
  defaultUserAgent: () => defaultUserAgent
});
module.exports = __toCommonJS(src_exports);
var import_node_config_provider = __nccwpck_require__(3461);
var import_os = __nccwpck_require__(2037);
var import_process = __nccwpck_require__(7282);

// src/crt-availability.ts
var crtAvailability = {
  isCrtAvailable: false
};

// src/is-crt-available.ts
var isCrtAvailable = /* @__PURE__ */ __name(() => {
  if (crtAvailability.isCrtAvailable) {
    return ["md/crt-avail"];
  }
  return null;
}, "isCrtAvailable");

// src/index.ts
var UA_APP_ID_ENV_NAME = "AWS_SDK_UA_APP_ID";
var UA_APP_ID_INI_NAME = "sdk-ua-app-id";
var defaultUserAgent = /* @__PURE__ */ __name(({ serviceId, clientVersion }) => {
  const sections = [
    // sdk-metadata
    ["aws-sdk-js", clientVersion],
    // ua-metadata
    ["ua", "2.0"],
    // os-metadata
    [`os/${(0, import_os.platform)()}`, (0, import_os.release)()],
    // language-metadata
    // ECMAScript edition doesn't matter in JS, so no version needed.
    ["lang/js"],
    ["md/nodejs", `${import_process.versions.node}`]
  ];
  const crtAvailable = isCrtAvailable();
  if (crtAvailable) {
    sections.push(crtAvailable);
  }
  if (serviceId) {
    sections.push([`api/${serviceId}`, clientVersion]);
  }
  if (import_process.env.AWS_EXECUTION_ENV) {
    sections.push([`exec-env/${import_process.env.AWS_EXECUTION_ENV}`]);
  }
  const appIdPromise = (0, import_node_config_provider.loadConfig)({
    environmentVariableSelector: (env2) => env2[UA_APP_ID_ENV_NAME],
    configFileSelector: (profile) => profile[UA_APP_ID_INI_NAME],
    default: void 0
  })();
  let resolvedUserAgent = void 0;
  return async () => {
    if (!resolvedUserAgent) {
      const appId = await appIdPromise;
      resolvedUserAgent = appId ? [...sections, [`app/${appId}`]] : [...sections];
    }
    return resolvedUserAgent;
  };
}, "defaultUserAgent");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 3098:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  CONFIG_USE_DUALSTACK_ENDPOINT: () => CONFIG_USE_DUALSTACK_ENDPOINT,
  CONFIG_USE_FIPS_ENDPOINT: () => CONFIG_USE_FIPS_ENDPOINT,
  DEFAULT_USE_DUALSTACK_ENDPOINT: () => DEFAULT_USE_DUALSTACK_ENDPOINT,
  DEFAULT_USE_FIPS_ENDPOINT: () => DEFAULT_USE_FIPS_ENDPOINT,
  ENV_USE_DUALSTACK_ENDPOINT: () => ENV_USE_DUALSTACK_ENDPOINT,
  ENV_USE_FIPS_ENDPOINT: () => ENV_USE_FIPS_ENDPOINT,
  NODE_REGION_CONFIG_FILE_OPTIONS: () => NODE_REGION_CONFIG_FILE_OPTIONS,
  NODE_REGION_CONFIG_OPTIONS: () => NODE_REGION_CONFIG_OPTIONS,
  NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS: () => NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS,
  NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS: () => NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS,
  REGION_ENV_NAME: () => REGION_ENV_NAME,
  REGION_INI_NAME: () => REGION_INI_NAME,
  getRegionInfo: () => getRegionInfo,
  resolveCustomEndpointsConfig: () => resolveCustomEndpointsConfig,
  resolveEndpointsConfig: () => resolveEndpointsConfig,
  resolveRegionConfig: () => resolveRegionConfig
});
module.exports = __toCommonJS(src_exports);

// src/endpointsConfig/NodeUseDualstackEndpointConfigOptions.ts
var import_util_config_provider = __nccwpck_require__(3375);
var ENV_USE_DUALSTACK_ENDPOINT = "AWS_USE_DUALSTACK_ENDPOINT";
var CONFIG_USE_DUALSTACK_ENDPOINT = "use_dualstack_endpoint";
var DEFAULT_USE_DUALSTACK_ENDPOINT = false;
var NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS = {
  environmentVariableSelector: (env) => (0, import_util_config_provider.booleanSelector)(env, ENV_USE_DUALSTACK_ENDPOINT, import_util_config_provider.SelectorType.ENV),
  configFileSelector: (profile) => (0, import_util_config_provider.booleanSelector)(profile, CONFIG_USE_DUALSTACK_ENDPOINT, import_util_config_provider.SelectorType.CONFIG),
  default: false
};

// src/endpointsConfig/NodeUseFipsEndpointConfigOptions.ts

var ENV_USE_FIPS_ENDPOINT = "AWS_USE_FIPS_ENDPOINT";
var CONFIG_USE_FIPS_ENDPOINT = "use_fips_endpoint";
var DEFAULT_USE_FIPS_ENDPOINT = false;
var NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS = {
  environmentVariableSelector: (env) => (0, import_util_config_provider.booleanSelector)(env, ENV_USE_FIPS_ENDPOINT, import_util_config_provider.SelectorType.ENV),
  configFileSelector: (profile) => (0, import_util_config_provider.booleanSelector)(profile, CONFIG_USE_FIPS_ENDPOINT, import_util_config_provider.SelectorType.CONFIG),
  default: false
};

// src/endpointsConfig/resolveCustomEndpointsConfig.ts
var import_util_middleware = __nccwpck_require__(2390);
var resolveCustomEndpointsConfig = /* @__PURE__ */ __name((input) => {
  const { endpoint, urlParser } = input;
  return {
    ...input,
    tls: input.tls ?? true,
    endpoint: (0, import_util_middleware.normalizeProvider)(typeof endpoint === "string" ? urlParser(endpoint) : endpoint),
    isCustomEndpoint: true,
    useDualstackEndpoint: (0, import_util_middleware.normalizeProvider)(input.useDualstackEndpoint ?? false)
  };
}, "resolveCustomEndpointsConfig");

// src/endpointsConfig/resolveEndpointsConfig.ts


// src/endpointsConfig/utils/getEndpointFromRegion.ts
var getEndpointFromRegion = /* @__PURE__ */ __name(async (input) => {
  const { tls = true } = input;
  const region = await input.region();
  const dnsHostRegex = new RegExp(/^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])$/);
  if (!dnsHostRegex.test(region)) {
    throw new Error("Invalid region in client config");
  }
  const useDualstackEndpoint = await input.useDualstackEndpoint();
  const useFipsEndpoint = await input.useFipsEndpoint();
  const { hostname } = await input.regionInfoProvider(region, { useDualstackEndpoint, useFipsEndpoint }) ?? {};
  if (!hostname) {
    throw new Error("Cannot resolve hostname from client config");
  }
  return input.urlParser(`${tls ? "https:" : "http:"}//${hostname}`);
}, "getEndpointFromRegion");

// src/endpointsConfig/resolveEndpointsConfig.ts
var resolveEndpointsConfig = /* @__PURE__ */ __name((input) => {
  const useDualstackEndpoint = (0, import_util_middleware.normalizeProvider)(input.useDualstackEndpoint ?? false);
  const { endpoint, useFipsEndpoint, urlParser } = input;
  return {
    ...input,
    tls: input.tls ?? true,
    endpoint: endpoint ? (0, import_util_middleware.normalizeProvider)(typeof endpoint === "string" ? urlParser(endpoint) : endpoint) : () => getEndpointFromRegion({ ...input, useDualstackEndpoint, useFipsEndpoint }),
    isCustomEndpoint: !!endpoint,
    useDualstackEndpoint
  };
}, "resolveEndpointsConfig");

// src/regionConfig/config.ts
var REGION_ENV_NAME = "AWS_REGION";
var REGION_INI_NAME = "region";
var NODE_REGION_CONFIG_OPTIONS = {
  environmentVariableSelector: (env) => env[REGION_ENV_NAME],
  configFileSelector: (profile) => profile[REGION_INI_NAME],
  default: () => {
    throw new Error("Region is missing");
  }
};
var NODE_REGION_CONFIG_FILE_OPTIONS = {
  preferredFile: "credentials"
};

// src/regionConfig/isFipsRegion.ts
var isFipsRegion = /* @__PURE__ */ __name((region) => typeof region === "string" && (region.startsWith("fips-") || region.endsWith("-fips")), "isFipsRegion");

// src/regionConfig/getRealRegion.ts
var getRealRegion = /* @__PURE__ */ __name((region) => isFipsRegion(region) ? ["fips-aws-global", "aws-fips"].includes(region) ? "us-east-1" : region.replace(/fips-(dkr-|prod-)?|-fips/, "") : region, "getRealRegion");

// src/regionConfig/resolveRegionConfig.ts
var resolveRegionConfig = /* @__PURE__ */ __name((input) => {
  const { region, useFipsEndpoint } = input;
  if (!region) {
    throw new Error("Region is missing");
  }
  return {
    ...input,
    region: async () => {
      if (typeof region === "string") {
        return getRealRegion(region);
      }
      const providedRegion = await region();
      return getRealRegion(providedRegion);
    },
    useFipsEndpoint: async () => {
      const providedRegion = typeof region === "string" ? region : await region();
      if (isFipsRegion(providedRegion)) {
        return true;
      }
      return typeof useFipsEndpoint !== "function" ? Promise.resolve(!!useFipsEndpoint) : useFipsEndpoint();
    }
  };
}, "resolveRegionConfig");

// src/regionInfo/getHostnameFromVariants.ts
var getHostnameFromVariants = /* @__PURE__ */ __name((variants = [], { useFipsEndpoint, useDualstackEndpoint }) => {
  var _a;
  return (_a = variants.find(
    ({ tags }) => useFipsEndpoint === tags.includes("fips") && useDualstackEndpoint === tags.includes("dualstack")
  )) == null ? void 0 : _a.hostname;
}, "getHostnameFromVariants");

// src/regionInfo/getResolvedHostname.ts
var getResolvedHostname = /* @__PURE__ */ __name((resolvedRegion, { regionHostname, partitionHostname }) => regionHostname ? regionHostname : partitionHostname ? partitionHostname.replace("{region}", resolvedRegion) : void 0, "getResolvedHostname");

// src/regionInfo/getResolvedPartition.ts
var getResolvedPartition = /* @__PURE__ */ __name((region, { partitionHash }) => Object.keys(partitionHash || {}).find((key) => partitionHash[key].regions.includes(region)) ?? "aws", "getResolvedPartition");

// src/regionInfo/getResolvedSigningRegion.ts
var getResolvedSigningRegion = /* @__PURE__ */ __name((hostname, { signingRegion, regionRegex, useFipsEndpoint }) => {
  if (signingRegion) {
    return signingRegion;
  } else if (useFipsEndpoint) {
    const regionRegexJs = regionRegex.replace("\\\\", "\\").replace(/^\^/g, "\\.").replace(/\$$/g, "\\.");
    const regionRegexmatchArray = hostname.match(regionRegexJs);
    if (regionRegexmatchArray) {
      return regionRegexmatchArray[0].slice(1, -1);
    }
  }
}, "getResolvedSigningRegion");

// src/regionInfo/getRegionInfo.ts
var getRegionInfo = /* @__PURE__ */ __name((region, {
  useFipsEndpoint = false,
  useDualstackEndpoint = false,
  signingService,
  regionHash,
  partitionHash
}) => {
  var _a, _b, _c, _d, _e;
  const partition = getResolvedPartition(region, { partitionHash });
  const resolvedRegion = region in regionHash ? region : ((_a = partitionHash[partition]) == null ? void 0 : _a.endpoint) ?? region;
  const hostnameOptions = { useFipsEndpoint, useDualstackEndpoint };
  const regionHostname = getHostnameFromVariants((_b = regionHash[resolvedRegion]) == null ? void 0 : _b.variants, hostnameOptions);
  const partitionHostname = getHostnameFromVariants((_c = partitionHash[partition]) == null ? void 0 : _c.variants, hostnameOptions);
  const hostname = getResolvedHostname(resolvedRegion, { regionHostname, partitionHostname });
  if (hostname === void 0) {
    throw new Error(`Endpoint resolution failed for: ${{ resolvedRegion, useFipsEndpoint, useDualstackEndpoint }}`);
  }
  const signingRegion = getResolvedSigningRegion(hostname, {
    signingRegion: (_d = regionHash[resolvedRegion]) == null ? void 0 : _d.signingRegion,
    regionRegex: partitionHash[partition].regionRegex,
    useFipsEndpoint
  });
  return {
    partition,
    signingService,
    hostname,
    ...signingRegion && { signingRegion },
    ...((_e = regionHash[resolvedRegion]) == null ? void 0 : _e.signingService) && {
      signingService: regionHash[resolvedRegion].signingService
    }
  };
}, "getRegionInfo");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 5829:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  DefaultIdentityProviderConfig: () => DefaultIdentityProviderConfig,
  EXPIRATION_MS: () => EXPIRATION_MS,
  HttpApiKeyAuthSigner: () => HttpApiKeyAuthSigner,
  HttpBearerAuthSigner: () => HttpBearerAuthSigner,
  NoAuthSigner: () => NoAuthSigner,
  RequestBuilder: () => RequestBuilder,
  createIsIdentityExpiredFunction: () => createIsIdentityExpiredFunction,
  createPaginator: () => createPaginator,
  doesIdentityRequireRefresh: () => doesIdentityRequireRefresh,
  getHttpAuthSchemeEndpointRuleSetPlugin: () => getHttpAuthSchemeEndpointRuleSetPlugin,
  getHttpAuthSchemePlugin: () => getHttpAuthSchemePlugin,
  getHttpSigningPlugin: () => getHttpSigningPlugin,
  getSmithyContext: () => getSmithyContext3,
  httpAuthSchemeEndpointRuleSetMiddlewareOptions: () => httpAuthSchemeEndpointRuleSetMiddlewareOptions,
  httpAuthSchemeMiddleware: () => httpAuthSchemeMiddleware,
  httpAuthSchemeMiddlewareOptions: () => httpAuthSchemeMiddlewareOptions,
  httpSigningMiddleware: () => httpSigningMiddleware,
  httpSigningMiddlewareOptions: () => httpSigningMiddlewareOptions,
  isIdentityExpired: () => isIdentityExpired,
  memoizeIdentityProvider: () => memoizeIdentityProvider,
  normalizeProvider: () => normalizeProvider,
  requestBuilder: () => requestBuilder
});
module.exports = __toCommonJS(src_exports);

// src/middleware-http-auth-scheme/httpAuthSchemeMiddleware.ts
var import_util_middleware = __nccwpck_require__(2390);
function convertHttpAuthSchemesToMap(httpAuthSchemes) {
  const map = /* @__PURE__ */ new Map();
  for (const scheme of httpAuthSchemes) {
    map.set(scheme.schemeId, scheme);
  }
  return map;
}
__name(convertHttpAuthSchemesToMap, "convertHttpAuthSchemesToMap");
var httpAuthSchemeMiddleware = /* @__PURE__ */ __name((config, mwOptions) => (next, context) => async (args) => {
  var _a;
  const options = config.httpAuthSchemeProvider(
    await mwOptions.httpAuthSchemeParametersProvider(config, context, args.input)
  );
  const authSchemes = convertHttpAuthSchemesToMap(config.httpAuthSchemes);
  const smithyContext = (0, import_util_middleware.getSmithyContext)(context);
  const failureReasons = [];
  for (const option of options) {
    const scheme = authSchemes.get(option.schemeId);
    if (!scheme) {
      failureReasons.push(`HttpAuthScheme \`${option.schemeId}\` was not enabled for this service.`);
      continue;
    }
    const identityProvider = scheme.identityProvider(await mwOptions.identityProviderConfigProvider(config));
    if (!identityProvider) {
      failureReasons.push(`HttpAuthScheme \`${option.schemeId}\` did not have an IdentityProvider configured.`);
      continue;
    }
    const { identityProperties = {}, signingProperties = {} } = ((_a = option.propertiesExtractor) == null ? void 0 : _a.call(option, config, context)) || {};
    option.identityProperties = Object.assign(option.identityProperties || {}, identityProperties);
    option.signingProperties = Object.assign(option.signingProperties || {}, signingProperties);
    smithyContext.selectedHttpAuthScheme = {
      httpAuthOption: option,
      identity: await identityProvider(option.identityProperties),
      signer: scheme.signer
    };
    break;
  }
  if (!smithyContext.selectedHttpAuthScheme) {
    throw new Error(failureReasons.join("\n"));
  }
  return next(args);
}, "httpAuthSchemeMiddleware");

// src/middleware-http-auth-scheme/getHttpAuthSchemeEndpointRuleSetPlugin.ts
var import_middleware_endpoint = __nccwpck_require__(2918);
var httpAuthSchemeEndpointRuleSetMiddlewareOptions = {
  step: "serialize",
  tags: ["HTTP_AUTH_SCHEME"],
  name: "httpAuthSchemeMiddleware",
  override: true,
  relation: "before",
  toMiddleware: import_middleware_endpoint.endpointMiddlewareOptions.name
};
var getHttpAuthSchemeEndpointRuleSetPlugin = /* @__PURE__ */ __name((config, {
  httpAuthSchemeParametersProvider,
  identityProviderConfigProvider
}) => ({
  applyToStack: (clientStack) => {
    clientStack.addRelativeTo(
      httpAuthSchemeMiddleware(config, {
        httpAuthSchemeParametersProvider,
        identityProviderConfigProvider
      }),
      httpAuthSchemeEndpointRuleSetMiddlewareOptions
    );
  }
}), "getHttpAuthSchemeEndpointRuleSetPlugin");

// src/middleware-http-auth-scheme/getHttpAuthSchemePlugin.ts
var import_middleware_serde = __nccwpck_require__(1238);
var httpAuthSchemeMiddlewareOptions = {
  step: "serialize",
  tags: ["HTTP_AUTH_SCHEME"],
  name: "httpAuthSchemeMiddleware",
  override: true,
  relation: "before",
  toMiddleware: import_middleware_serde.serializerMiddlewareOption.name
};
var getHttpAuthSchemePlugin = /* @__PURE__ */ __name((config, {
  httpAuthSchemeParametersProvider,
  identityProviderConfigProvider
}) => ({
  applyToStack: (clientStack) => {
    clientStack.addRelativeTo(
      httpAuthSchemeMiddleware(config, {
        httpAuthSchemeParametersProvider,
        identityProviderConfigProvider
      }),
      httpAuthSchemeMiddlewareOptions
    );
  }
}), "getHttpAuthSchemePlugin");

// src/middleware-http-signing/httpSigningMiddleware.ts
var import_protocol_http = __nccwpck_require__(4418);

var defaultErrorHandler = /* @__PURE__ */ __name((signingProperties) => (error) => {
  throw error;
}, "defaultErrorHandler");
var defaultSuccessHandler = /* @__PURE__ */ __name((httpResponse, signingProperties) => {
}, "defaultSuccessHandler");
var httpSigningMiddleware = /* @__PURE__ */ __name((config) => (next, context) => async (args) => {
  if (!import_protocol_http.HttpRequest.isInstance(args.request)) {
    return next(args);
  }
  const smithyContext = (0, import_util_middleware.getSmithyContext)(context);
  const scheme = smithyContext.selectedHttpAuthScheme;
  if (!scheme) {
    throw new Error(`No HttpAuthScheme was selected: unable to sign request`);
  }
  const {
    httpAuthOption: { signingProperties = {} },
    identity,
    signer
  } = scheme;
  const output = await next({
    ...args,
    request: await signer.sign(args.request, identity, signingProperties)
  }).catch((signer.errorHandler || defaultErrorHandler)(signingProperties));
  (signer.successHandler || defaultSuccessHandler)(output.response, signingProperties);
  return output;
}, "httpSigningMiddleware");

// src/middleware-http-signing/getHttpSigningMiddleware.ts
var import_middleware_retry = __nccwpck_require__(6039);
var httpSigningMiddlewareOptions = {
  step: "finalizeRequest",
  tags: ["HTTP_SIGNING"],
  name: "httpSigningMiddleware",
  aliases: ["apiKeyMiddleware", "tokenMiddleware", "awsAuthMiddleware"],
  override: true,
  relation: "after",
  toMiddleware: import_middleware_retry.retryMiddlewareOptions.name
};
var getHttpSigningPlugin = /* @__PURE__ */ __name((config) => ({
  applyToStack: (clientStack) => {
    clientStack.addRelativeTo(httpSigningMiddleware(config), httpSigningMiddlewareOptions);
  }
}), "getHttpSigningPlugin");

// src/util-identity-and-auth/DefaultIdentityProviderConfig.ts
var _DefaultIdentityProviderConfig = class _DefaultIdentityProviderConfig {
  /**
   * Creates an IdentityProviderConfig with a record of scheme IDs to identity providers.
   *
   * @param config scheme IDs and identity providers to configure
   */
  constructor(config) {
    this.authSchemes = /* @__PURE__ */ new Map();
    for (const [key, value] of Object.entries(config)) {
      if (value !== void 0) {
        this.authSchemes.set(key, value);
      }
    }
  }
  getIdentityProvider(schemeId) {
    return this.authSchemes.get(schemeId);
  }
};
__name(_DefaultIdentityProviderConfig, "DefaultIdentityProviderConfig");
var DefaultIdentityProviderConfig = _DefaultIdentityProviderConfig;

// src/util-identity-and-auth/httpAuthSchemes/httpApiKeyAuth.ts

var import_types = __nccwpck_require__(5756);
var _HttpApiKeyAuthSigner = class _HttpApiKeyAuthSigner {
  async sign(httpRequest, identity, signingProperties) {
    if (!signingProperties) {
      throw new Error(
        "request could not be signed with `apiKey` since the `name` and `in` signer properties are missing"
      );
    }
    if (!signingProperties.name) {
      throw new Error("request could not be signed with `apiKey` since the `name` signer property is missing");
    }
    if (!signingProperties.in) {
      throw new Error("request could not be signed with `apiKey` since the `in` signer property is missing");
    }
    if (!identity.apiKey) {
      throw new Error("request could not be signed with `apiKey` since the `apiKey` is not defined");
    }
    const clonedRequest = import_protocol_http.HttpRequest.clone(httpRequest);
    if (signingProperties.in === import_types.HttpApiKeyAuthLocation.QUERY) {
      clonedRequest.query[signingProperties.name] = identity.apiKey;
    } else if (signingProperties.in === import_types.HttpApiKeyAuthLocation.HEADER) {
      clonedRequest.headers[signingProperties.name] = signingProperties.scheme ? `${signingProperties.scheme} ${identity.apiKey}` : identity.apiKey;
    } else {
      throw new Error(
        "request can only be signed with `apiKey` locations `query` or `header`, but found: `" + signingProperties.in + "`"
      );
    }
    return clonedRequest;
  }
};
__name(_HttpApiKeyAuthSigner, "HttpApiKeyAuthSigner");
var HttpApiKeyAuthSigner = _HttpApiKeyAuthSigner;

// src/util-identity-and-auth/httpAuthSchemes/httpBearerAuth.ts

var _HttpBearerAuthSigner = class _HttpBearerAuthSigner {
  async sign(httpRequest, identity, signingProperties) {
    const clonedRequest = import_protocol_http.HttpRequest.clone(httpRequest);
    if (!identity.token) {
      throw new Error("request could not be signed with `token` since the `token` is not defined");
    }
    clonedRequest.headers["Authorization"] = `Bearer ${identity.token}`;
    return clonedRequest;
  }
};
__name(_HttpBearerAuthSigner, "HttpBearerAuthSigner");
var HttpBearerAuthSigner = _HttpBearerAuthSigner;

// src/util-identity-and-auth/httpAuthSchemes/noAuth.ts
var _NoAuthSigner = class _NoAuthSigner {
  async sign(httpRequest, identity, signingProperties) {
    return httpRequest;
  }
};
__name(_NoAuthSigner, "NoAuthSigner");
var NoAuthSigner = _NoAuthSigner;

// src/util-identity-and-auth/memoizeIdentityProvider.ts
var createIsIdentityExpiredFunction = /* @__PURE__ */ __name((expirationMs) => (identity) => doesIdentityRequireRefresh(identity) && identity.expiration.getTime() - Date.now() < expirationMs, "createIsIdentityExpiredFunction");
var EXPIRATION_MS = 3e5;
var isIdentityExpired = createIsIdentityExpiredFunction(EXPIRATION_MS);
var doesIdentityRequireRefresh = /* @__PURE__ */ __name((identity) => identity.expiration !== void 0, "doesIdentityRequireRefresh");
var memoizeIdentityProvider = /* @__PURE__ */ __name((provider, isExpired, requiresRefresh) => {
  if (provider === void 0) {
    return void 0;
  }
  const normalizedProvider = typeof provider !== "function" ? async () => Promise.resolve(provider) : provider;
  let resolved;
  let pending;
  let hasResult;
  let isConstant = false;
  const coalesceProvider = /* @__PURE__ */ __name(async (options) => {
    if (!pending) {
      pending = normalizedProvider(options);
    }
    try {
      resolved = await pending;
      hasResult = true;
      isConstant = false;
    } finally {
      pending = void 0;
    }
    return resolved;
  }, "coalesceProvider");
  if (isExpired === void 0) {
    return async (options) => {
      if (!hasResult || (options == null ? void 0 : options.forceRefresh)) {
        resolved = await coalesceProvider(options);
      }
      return resolved;
    };
  }
  return async (options) => {
    if (!hasResult || (options == null ? void 0 : options.forceRefresh)) {
      resolved = await coalesceProvider(options);
    }
    if (isConstant) {
      return resolved;
    }
    if (!requiresRefresh(resolved)) {
      isConstant = true;
      return resolved;
    }
    if (isExpired(resolved)) {
      await coalesceProvider(options);
      return resolved;
    }
    return resolved;
  };
}, "memoizeIdentityProvider");

// src/getSmithyContext.ts

var getSmithyContext3 = /* @__PURE__ */ __name((context) => context[import_types.SMITHY_CONTEXT_KEY] || (context[import_types.SMITHY_CONTEXT_KEY] = {}), "getSmithyContext");

// src/normalizeProvider.ts
var normalizeProvider = /* @__PURE__ */ __name((input) => {
  if (typeof input === "function")
    return input;
  const promisified = Promise.resolve(input);
  return () => promisified;
}, "normalizeProvider");

// src/protocols/requestBuilder.ts

var import_smithy_client = __nccwpck_require__(3570);
function requestBuilder(input, context) {
  return new RequestBuilder(input, context);
}
__name(requestBuilder, "requestBuilder");
var _RequestBuilder = class _RequestBuilder {
  constructor(input, context) {
    this.input = input;
    this.context = context;
    this.query = {};
    this.method = "";
    this.headers = {};
    this.path = "";
    this.body = null;
    this.hostname = "";
    this.resolvePathStack = [];
  }
  async build() {
    const { hostname, protocol = "https", port, path: basePath } = await this.context.endpoint();
    this.path = basePath;
    for (const resolvePath of this.resolvePathStack) {
      resolvePath(this.path);
    }
    return new import_protocol_http.HttpRequest({
      protocol,
      hostname: this.hostname || hostname,
      port,
      method: this.method,
      path: this.path,
      query: this.query,
      body: this.body,
      headers: this.headers
    });
  }
  /**
   * Brevity setter for "hostname".
   */
  hn(hostname) {
    this.hostname = hostname;
    return this;
  }
  /**
   * Brevity initial builder for "basepath".
   */
  bp(uriLabel) {
    this.resolvePathStack.push((basePath) => {
      this.path = `${(basePath == null ? void 0 : basePath.endsWith("/")) ? basePath.slice(0, -1) : basePath || ""}` + uriLabel;
    });
    return this;
  }
  /**
   * Brevity incremental builder for "path".
   */
  p(memberName, labelValueProvider, uriLabel, isGreedyLabel) {
    this.resolvePathStack.push((path) => {
      this.path = (0, import_smithy_client.resolvedPath)(path, this.input, memberName, labelValueProvider, uriLabel, isGreedyLabel);
    });
    return this;
  }
  /**
   * Brevity setter for "headers".
   */
  h(headers) {
    this.headers = headers;
    return this;
  }
  /**
   * Brevity setter for "query".
   */
  q(query) {
    this.query = query;
    return this;
  }
  /**
   * Brevity setter for "body".
   */
  b(body) {
    this.body = body;
    return this;
  }
  /**
   * Brevity setter for "method".
   */
  m(method) {
    this.method = method;
    return this;
  }
};
__name(_RequestBuilder, "RequestBuilder");
var RequestBuilder = _RequestBuilder;

// src/pagination/createPaginator.ts
var makePagedClientRequest = /* @__PURE__ */ __name(async (CommandCtor, client, input, ...args) => {
  return await client.send(new CommandCtor(input), ...args);
}, "makePagedClientRequest");
function createPaginator(ClientCtor, CommandCtor, inputTokenName, outputTokenName, pageSizeTokenName) {
  return /* @__PURE__ */ __name(async function* paginateOperation(config, input, ...additionalArguments) {
    let token = config.startingToken || void 0;
    let hasNext = true;
    let page;
    while (hasNext) {
      input[inputTokenName] = token;
      if (pageSizeTokenName) {
        input[pageSizeTokenName] = input[pageSizeTokenName] ?? config.pageSize;
      }
      if (config.client instanceof ClientCtor) {
        page = await makePagedClientRequest(CommandCtor, config.client, input, ...additionalArguments);
      } else {
        throw new Error(`Invalid client, expected instance of ${ClientCtor.name}`);
      }
      yield page;
      const prevToken = token;
      token = get(page, outputTokenName);
      hasNext = !!(token && (!config.stopOnSameToken || token !== prevToken));
    }
    return void 0;
  }, "paginateOperation");
}
__name(createPaginator, "createPaginator");
var get = /* @__PURE__ */ __name((fromObject, path) => {
  let cursor = fromObject;
  const pathComponents = path.split(".");
  for (const step of pathComponents) {
    if (!cursor || typeof cursor !== "object") {
      return void 0;
    }
    cursor = cursor[step];
  }
  return cursor;
}, "get");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 7477:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  DEFAULT_MAX_RETRIES: () => DEFAULT_MAX_RETRIES,
  DEFAULT_TIMEOUT: () => DEFAULT_TIMEOUT,
  ENV_CMDS_AUTH_TOKEN: () => ENV_CMDS_AUTH_TOKEN,
  ENV_CMDS_FULL_URI: () => ENV_CMDS_FULL_URI,
  ENV_CMDS_RELATIVE_URI: () => ENV_CMDS_RELATIVE_URI,
  Endpoint: () => Endpoint,
  fromContainerMetadata: () => fromContainerMetadata,
  fromInstanceMetadata: () => fromInstanceMetadata,
  getInstanceMetadataEndpoint: () => getInstanceMetadataEndpoint,
  httpRequest: () => httpRequest,
  providerConfigFromInit: () => providerConfigFromInit
});
module.exports = __toCommonJS(src_exports);

// src/fromContainerMetadata.ts

var import_url = __nccwpck_require__(7310);

// src/remoteProvider/httpRequest.ts
var import_property_provider = __nccwpck_require__(9721);
var import_buffer = __nccwpck_require__(4300);
var import_http = __nccwpck_require__(3685);
function httpRequest(options) {
  return new Promise((resolve, reject) => {
    var _a;
    const req = (0, import_http.request)({
      method: "GET",
      ...options,
      // Node.js http module doesn't accept hostname with square brackets
      // Refs: https://github.com/nodejs/node/issues/39738
      hostname: (_a = options.hostname) == null ? void 0 : _a.replace(/^\[(.+)\]$/, "$1")
    });
    req.on("error", (err) => {
      reject(Object.assign(new import_property_provider.ProviderError("Unable to connect to instance metadata service"), err));
      req.destroy();
    });
    req.on("timeout", () => {
      reject(new import_property_provider.ProviderError("TimeoutError from instance metadata service"));
      req.destroy();
    });
    req.on("response", (res) => {
      const { statusCode = 400 } = res;
      if (statusCode < 200 || 300 <= statusCode) {
        reject(
          Object.assign(new import_property_provider.ProviderError("Error response received from instance metadata service"), { statusCode })
        );
        req.destroy();
      }
      const chunks = [];
      res.on("data", (chunk) => {
        chunks.push(chunk);
      });
      res.on("end", () => {
        resolve(import_buffer.Buffer.concat(chunks));
        req.destroy();
      });
    });
    req.end();
  });
}
__name(httpRequest, "httpRequest");

// src/remoteProvider/ImdsCredentials.ts
var isImdsCredentials = /* @__PURE__ */ __name((arg) => Boolean(arg) && typeof arg === "object" && typeof arg.AccessKeyId === "string" && typeof arg.SecretAccessKey === "string" && typeof arg.Token === "string" && typeof arg.Expiration === "string", "isImdsCredentials");
var fromImdsCredentials = /* @__PURE__ */ __name((creds) => ({
  accessKeyId: creds.AccessKeyId,
  secretAccessKey: creds.SecretAccessKey,
  sessionToken: creds.Token,
  expiration: new Date(creds.Expiration),
  ...creds.AccountId && { accountId: creds.AccountId }
}), "fromImdsCredentials");

// src/remoteProvider/RemoteProviderInit.ts
var DEFAULT_TIMEOUT = 1e3;
var DEFAULT_MAX_RETRIES = 0;
var providerConfigFromInit = /* @__PURE__ */ __name(({
  maxRetries = DEFAULT_MAX_RETRIES,
  timeout = DEFAULT_TIMEOUT
}) => ({ maxRetries, timeout }), "providerConfigFromInit");

// src/remoteProvider/retry.ts
var retry = /* @__PURE__ */ __name((toRetry, maxRetries) => {
  let promise = toRetry();
  for (let i = 0; i < maxRetries; i++) {
    promise = promise.catch(toRetry);
  }
  return promise;
}, "retry");

// src/fromContainerMetadata.ts
var ENV_CMDS_FULL_URI = "AWS_CONTAINER_CREDENTIALS_FULL_URI";
var ENV_CMDS_RELATIVE_URI = "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI";
var ENV_CMDS_AUTH_TOKEN = "AWS_CONTAINER_AUTHORIZATION_TOKEN";
var fromContainerMetadata = /* @__PURE__ */ __name((init = {}) => {
  const { timeout, maxRetries } = providerConfigFromInit(init);
  return () => retry(async () => {
    const requestOptions = await getCmdsUri({ logger: init.logger });
    const credsResponse = JSON.parse(await requestFromEcsImds(timeout, requestOptions));
    if (!isImdsCredentials(credsResponse)) {
      throw new import_property_provider.CredentialsProviderError("Invalid response received from instance metadata service.", {
        logger: init.logger
      });
    }
    return fromImdsCredentials(credsResponse);
  }, maxRetries);
}, "fromContainerMetadata");
var requestFromEcsImds = /* @__PURE__ */ __name(async (timeout, options) => {
  if (process.env[ENV_CMDS_AUTH_TOKEN]) {
    options.headers = {
      ...options.headers,
      Authorization: process.env[ENV_CMDS_AUTH_TOKEN]
    };
  }
  const buffer = await httpRequest({
    ...options,
    timeout
  });
  return buffer.toString();
}, "requestFromEcsImds");
var CMDS_IP = "169.254.170.2";
var GREENGRASS_HOSTS = {
  localhost: true,
  "127.0.0.1": true
};
var GREENGRASS_PROTOCOLS = {
  "http:": true,
  "https:": true
};
var getCmdsUri = /* @__PURE__ */ __name(async ({ logger }) => {
  if (process.env[ENV_CMDS_RELATIVE_URI]) {
    return {
      hostname: CMDS_IP,
      path: process.env[ENV_CMDS_RELATIVE_URI]
    };
  }
  if (process.env[ENV_CMDS_FULL_URI]) {
    const parsed = (0, import_url.parse)(process.env[ENV_CMDS_FULL_URI]);
    if (!parsed.hostname || !(parsed.hostname in GREENGRASS_HOSTS)) {
      throw new import_property_provider.CredentialsProviderError(`${parsed.hostname} is not a valid container metadata service hostname`, {
        tryNextLink: false,
        logger
      });
    }
    if (!parsed.protocol || !(parsed.protocol in GREENGRASS_PROTOCOLS)) {
      throw new import_property_provider.CredentialsProviderError(`${parsed.protocol} is not a valid container metadata service protocol`, {
        tryNextLink: false,
        logger
      });
    }
    return {
      ...parsed,
      port: parsed.port ? parseInt(parsed.port, 10) : void 0
    };
  }
  throw new import_property_provider.CredentialsProviderError(
    `The container metadata credential provider cannot be used unless the ${ENV_CMDS_RELATIVE_URI} or ${ENV_CMDS_FULL_URI} environment variable is set`,
    {
      tryNextLink: false,
      logger
    }
  );
}, "getCmdsUri");

// src/fromInstanceMetadata.ts



// src/error/InstanceMetadataV1FallbackError.ts

var _InstanceMetadataV1FallbackError = class _InstanceMetadataV1FallbackError extends import_property_provider.CredentialsProviderError {
  constructor(message, tryNextLink = true) {
    super(message, tryNextLink);
    this.tryNextLink = tryNextLink;
    this.name = "InstanceMetadataV1FallbackError";
    Object.setPrototypeOf(this, _InstanceMetadataV1FallbackError.prototype);
  }
};
__name(_InstanceMetadataV1FallbackError, "InstanceMetadataV1FallbackError");
var InstanceMetadataV1FallbackError = _InstanceMetadataV1FallbackError;

// src/utils/getInstanceMetadataEndpoint.ts
var import_node_config_provider = __nccwpck_require__(3461);
var import_url_parser = __nccwpck_require__(4681);

// src/config/Endpoint.ts
var Endpoint = /* @__PURE__ */ ((Endpoint2) => {
  Endpoint2["IPv4"] = "http://169.254.169.254";
  Endpoint2["IPv6"] = "http://[fd00:ec2::254]";
  return Endpoint2;
})(Endpoint || {});

// src/config/EndpointConfigOptions.ts
var ENV_ENDPOINT_NAME = "AWS_EC2_METADATA_SERVICE_ENDPOINT";
var CONFIG_ENDPOINT_NAME = "ec2_metadata_service_endpoint";
var ENDPOINT_CONFIG_OPTIONS = {
  environmentVariableSelector: (env) => env[ENV_ENDPOINT_NAME],
  configFileSelector: (profile) => profile[CONFIG_ENDPOINT_NAME],
  default: void 0
};

// src/config/EndpointMode.ts
var EndpointMode = /* @__PURE__ */ ((EndpointMode2) => {
  EndpointMode2["IPv4"] = "IPv4";
  EndpointMode2["IPv6"] = "IPv6";
  return EndpointMode2;
})(EndpointMode || {});

// src/config/EndpointModeConfigOptions.ts
var ENV_ENDPOINT_MODE_NAME = "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE";
var CONFIG_ENDPOINT_MODE_NAME = "ec2_metadata_service_endpoint_mode";
var ENDPOINT_MODE_CONFIG_OPTIONS = {
  environmentVariableSelector: (env) => env[ENV_ENDPOINT_MODE_NAME],
  configFileSelector: (profile) => profile[CONFIG_ENDPOINT_MODE_NAME],
  default: "IPv4" /* IPv4 */
};

// src/utils/getInstanceMetadataEndpoint.ts
var getInstanceMetadataEndpoint = /* @__PURE__ */ __name(async () => (0, import_url_parser.parseUrl)(await getFromEndpointConfig() || await getFromEndpointModeConfig()), "getInstanceMetadataEndpoint");
var getFromEndpointConfig = /* @__PURE__ */ __name(async () => (0, import_node_config_provider.loadConfig)(ENDPOINT_CONFIG_OPTIONS)(), "getFromEndpointConfig");
var getFromEndpointModeConfig = /* @__PURE__ */ __name(async () => {
  const endpointMode = await (0, import_node_config_provider.loadConfig)(ENDPOINT_MODE_CONFIG_OPTIONS)();
  switch (endpointMode) {
    case "IPv4" /* IPv4 */:
      return "http://169.254.169.254" /* IPv4 */;
    case "IPv6" /* IPv6 */:
      return "http://[fd00:ec2::254]" /* IPv6 */;
    default:
      throw new Error(`Unsupported endpoint mode: ${endpointMode}. Select from ${Object.values(EndpointMode)}`);
  }
}, "getFromEndpointModeConfig");

// src/utils/getExtendedInstanceMetadataCredentials.ts
var STATIC_STABILITY_REFRESH_INTERVAL_SECONDS = 5 * 60;
var STATIC_STABILITY_REFRESH_INTERVAL_JITTER_WINDOW_SECONDS = 5 * 60;
var STATIC_STABILITY_DOC_URL = "https://docs.aws.amazon.com/sdkref/latest/guide/feature-static-credentials.html";
var getExtendedInstanceMetadataCredentials = /* @__PURE__ */ __name((credentials, logger) => {
  const refreshInterval = STATIC_STABILITY_REFRESH_INTERVAL_SECONDS + Math.floor(Math.random() * STATIC_STABILITY_REFRESH_INTERVAL_JITTER_WINDOW_SECONDS);
  const newExpiration = new Date(Date.now() + refreshInterval * 1e3);
  logger.warn(
    `Attempting credential expiration extension due to a credential service availability issue. A refresh of these credentials will be attempted after ${new Date(newExpiration)}.
For more information, please visit: ` + STATIC_STABILITY_DOC_URL
  );
  const originalExpiration = credentials.originalExpiration ?? credentials.expiration;
  return {
    ...credentials,
    ...originalExpiration ? { originalExpiration } : {},
    expiration: newExpiration
  };
}, "getExtendedInstanceMetadataCredentials");

// src/utils/staticStabilityProvider.ts
var staticStabilityProvider = /* @__PURE__ */ __name((provider, options = {}) => {
  const logger = (options == null ? void 0 : options.logger) || console;
  let pastCredentials;
  return async () => {
    let credentials;
    try {
      credentials = await provider();
      if (credentials.expiration && credentials.expiration.getTime() < Date.now()) {
        credentials = getExtendedInstanceMetadataCredentials(credentials, logger);
      }
    } catch (e) {
      if (pastCredentials) {
        logger.warn("Credential renew failed: ", e);
        credentials = getExtendedInstanceMetadataCredentials(pastCredentials, logger);
      } else {
        throw e;
      }
    }
    pastCredentials = credentials;
    return credentials;
  };
}, "staticStabilityProvider");

// src/fromInstanceMetadata.ts
var IMDS_PATH = "/latest/meta-data/iam/security-credentials/";
var IMDS_TOKEN_PATH = "/latest/api/token";
var AWS_EC2_METADATA_V1_DISABLED = "AWS_EC2_METADATA_V1_DISABLED";
var PROFILE_AWS_EC2_METADATA_V1_DISABLED = "ec2_metadata_v1_disabled";
var X_AWS_EC2_METADATA_TOKEN = "x-aws-ec2-metadata-token";
var fromInstanceMetadata = /* @__PURE__ */ __name((init = {}) => staticStabilityProvider(getInstanceMetadataProvider(init), { logger: init.logger }), "fromInstanceMetadata");
var getInstanceMetadataProvider = /* @__PURE__ */ __name((init = {}) => {
  let disableFetchToken = false;
  const { logger, profile } = init;
  const { timeout, maxRetries } = providerConfigFromInit(init);
  const getCredentials = /* @__PURE__ */ __name(async (maxRetries2, options) => {
    var _a;
    const isImdsV1Fallback = disableFetchToken || ((_a = options.headers) == null ? void 0 : _a[X_AWS_EC2_METADATA_TOKEN]) == null;
    if (isImdsV1Fallback) {
      let fallbackBlockedFromProfile = false;
      let fallbackBlockedFromProcessEnv = false;
      const configValue = await (0, import_node_config_provider.loadConfig)(
        {
          environmentVariableSelector: (env) => {
            const envValue = env[AWS_EC2_METADATA_V1_DISABLED];
            fallbackBlockedFromProcessEnv = !!envValue && envValue !== "false";
            if (envValue === void 0) {
              throw new import_property_provider.CredentialsProviderError(
                `${AWS_EC2_METADATA_V1_DISABLED} not set in env, checking config file next.`,
                { logger: init.logger }
              );
            }
            return fallbackBlockedFromProcessEnv;
          },
          configFileSelector: (profile2) => {
            const profileValue = profile2[PROFILE_AWS_EC2_METADATA_V1_DISABLED];
            fallbackBlockedFromProfile = !!profileValue && profileValue !== "false";
            return fallbackBlockedFromProfile;
          },
          default: false
        },
        {
          profile
        }
      )();
      if (init.ec2MetadataV1Disabled || configValue) {
        const causes = [];
        if (init.ec2MetadataV1Disabled)
          causes.push("credential provider initialization (runtime option ec2MetadataV1Disabled)");
        if (fallbackBlockedFromProfile)
          causes.push(`config file profile (${PROFILE_AWS_EC2_METADATA_V1_DISABLED})`);
        if (fallbackBlockedFromProcessEnv)
          causes.push(`process environment variable (${AWS_EC2_METADATA_V1_DISABLED})`);
        throw new InstanceMetadataV1FallbackError(
          `AWS EC2 Metadata v1 fallback has been blocked by AWS SDK configuration in the following: [${causes.join(
            ", "
          )}].`
        );
      }
    }
    const imdsProfile = (await retry(async () => {
      let profile2;
      try {
        profile2 = await getProfile(options);
      } catch (err) {
        if (err.statusCode === 401) {
          disableFetchToken = false;
        }
        throw err;
      }
      return profile2;
    }, maxRetries2)).trim();
    return retry(async () => {
      let creds;
      try {
        creds = await getCredentialsFromProfile(imdsProfile, options, init);
      } catch (err) {
        if (err.statusCode === 401) {
          disableFetchToken = false;
        }
        throw err;
      }
      return creds;
    }, maxRetries2);
  }, "getCredentials");
  return async () => {
    const endpoint = await getInstanceMetadataEndpoint();
    if (disableFetchToken) {
      logger == null ? void 0 : logger.debug("AWS SDK Instance Metadata", "using v1 fallback (no token fetch)");
      return getCredentials(maxRetries, { ...endpoint, timeout });
    } else {
      let token;
      try {
        token = (await getMetadataToken({ ...endpoint, timeout })).toString();
      } catch (error) {
        if ((error == null ? void 0 : error.statusCode) === 400) {
          throw Object.assign(error, {
            message: "EC2 Metadata token request returned error"
          });
        } else if (error.message === "TimeoutError" || [403, 404, 405].includes(error.statusCode)) {
          disableFetchToken = true;
        }
        logger == null ? void 0 : logger.debug("AWS SDK Instance Metadata", "using v1 fallback (initial)");
        return getCredentials(maxRetries, { ...endpoint, timeout });
      }
      return getCredentials(maxRetries, {
        ...endpoint,
        headers: {
          [X_AWS_EC2_METADATA_TOKEN]: token
        },
        timeout
      });
    }
  };
}, "getInstanceMetadataProvider");
var getMetadataToken = /* @__PURE__ */ __name(async (options) => httpRequest({
  ...options,
  path: IMDS_TOKEN_PATH,
  method: "PUT",
  headers: {
    "x-aws-ec2-metadata-token-ttl-seconds": "21600"
  }
}), "getMetadataToken");
var getProfile = /* @__PURE__ */ __name(async (options) => (await httpRequest({ ...options, path: IMDS_PATH })).toString(), "getProfile");
var getCredentialsFromProfile = /* @__PURE__ */ __name(async (profile, options, init) => {
  const credentialsResponse = JSON.parse(
    (await httpRequest({
      ...options,
      path: IMDS_PATH + profile
    })).toString()
  );
  if (!isImdsCredentials(credentialsResponse)) {
    throw new import_property_provider.CredentialsProviderError("Invalid response received from instance metadata service.", {
      logger: init.logger
    });
  }
  return fromImdsCredentials(credentialsResponse);
}, "getCredentialsFromProfile");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 2687:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  FetchHttpHandler: () => FetchHttpHandler,
  keepAliveSupport: () => keepAliveSupport,
  streamCollector: () => streamCollector
});
module.exports = __toCommonJS(src_exports);

// src/fetch-http-handler.ts
var import_protocol_http = __nccwpck_require__(4418);
var import_querystring_builder = __nccwpck_require__(8031);

// src/request-timeout.ts
function requestTimeout(timeoutInMs = 0) {
  return new Promise((resolve, reject) => {
    if (timeoutInMs) {
      setTimeout(() => {
        const timeoutError = new Error(`Request did not complete within ${timeoutInMs} ms`);
        timeoutError.name = "TimeoutError";
        reject(timeoutError);
      }, timeoutInMs);
    }
  });
}
__name(requestTimeout, "requestTimeout");

// src/fetch-http-handler.ts
var keepAliveSupport = {
  supported: void 0
};
var _FetchHttpHandler = class _FetchHttpHandler {
  /**
   * @returns the input if it is an HttpHandler of any class,
   * or instantiates a new instance of this handler.
   */
  static create(instanceOrOptions) {
    if (typeof (instanceOrOptions == null ? void 0 : instanceOrOptions.handle) === "function") {
      return instanceOrOptions;
    }
    return new _FetchHttpHandler(instanceOrOptions);
  }
  constructor(options) {
    if (typeof options === "function") {
      this.configProvider = options().then((opts) => opts || {});
    } else {
      this.config = options ?? {};
      this.configProvider = Promise.resolve(this.config);
    }
    if (keepAliveSupport.supported === void 0) {
      keepAliveSupport.supported = Boolean(
        typeof Request !== "undefined" && "keepalive" in new Request("https://[::1]")
      );
    }
  }
  destroy() {
  }
  async handle(request, { abortSignal } = {}) {
    if (!this.config) {
      this.config = await this.configProvider;
    }
    const requestTimeoutInMs = this.config.requestTimeout;
    const keepAlive = this.config.keepAlive === true;
    const credentials = this.config.credentials;
    if (abortSignal == null ? void 0 : abortSignal.aborted) {
      const abortError = new Error("Request aborted");
      abortError.name = "AbortError";
      return Promise.reject(abortError);
    }
    let path = request.path;
    const queryString = (0, import_querystring_builder.buildQueryString)(request.query || {});
    if (queryString) {
      path += `?${queryString}`;
    }
    if (request.fragment) {
      path += `#${request.fragment}`;
    }
    let auth = "";
    if (request.username != null || request.password != null) {
      const username = request.username ?? "";
      const password = request.password ?? "";
      auth = `${username}:${password}@`;
    }
    const { port, method } = request;
    const url = `${request.protocol}//${auth}${request.hostname}${port ? `:${port}` : ""}${path}`;
    const body = method === "GET" || method === "HEAD" ? void 0 : request.body;
    const requestOptions = {
      body,
      headers: new Headers(request.headers),
      method,
      credentials
    };
    if (body) {
      requestOptions.duplex = "half";
    }
    if (typeof AbortController !== "undefined") {
      requestOptions.signal = abortSignal;
    }
    if (keepAliveSupport.supported) {
      requestOptions.keepalive = keepAlive;
    }
    let removeSignalEventListener = /* @__PURE__ */ __name(() => {
    }, "removeSignalEventListener");
    const fetchRequest = new Request(url, requestOptions);
    const raceOfPromises = [
      fetch(fetchRequest).then((response) => {
        const fetchHeaders = response.headers;
        const transformedHeaders = {};
        for (const pair of fetchHeaders.entries()) {
          transformedHeaders[pair[0]] = pair[1];
        }
        const hasReadableStream = response.body != void 0;
        if (!hasReadableStream) {
          return response.blob().then((body2) => ({
            response: new import_protocol_http.HttpResponse({
              headers: transformedHeaders,
              reason: response.statusText,
              statusCode: response.status,
              body: body2
            })
          }));
        }
        return {
          response: new import_protocol_http.HttpResponse({
            headers: transformedHeaders,
            reason: response.statusText,
            statusCode: response.status,
            body: response.body
          })
        };
      }),
      requestTimeout(requestTimeoutInMs)
    ];
    if (abortSignal) {
      raceOfPromises.push(
        new Promise((resolve, reject) => {
          const onAbort = /* @__PURE__ */ __name(() => {
            const abortError = new Error("Request aborted");
            abortError.name = "AbortError";
            reject(abortError);
          }, "onAbort");
          if (typeof abortSignal.addEventListener === "function") {
            const signal = abortSignal;
            signal.addEventListener("abort", onAbort, { once: true });
            removeSignalEventListener = /* @__PURE__ */ __name(() => signal.removeEventListener("abort", onAbort), "removeSignalEventListener");
          } else {
            abortSignal.onabort = onAbort;
          }
        })
      );
    }
    return Promise.race(raceOfPromises).finally(removeSignalEventListener);
  }
  updateHttpClientConfig(key, value) {
    this.config = void 0;
    this.configProvider = this.configProvider.then((config) => {
      config[key] = value;
      return config;
    });
  }
  httpHandlerConfigs() {
    return this.config ?? {};
  }
};
__name(_FetchHttpHandler, "FetchHttpHandler");
var FetchHttpHandler = _FetchHttpHandler;

// src/stream-collector.ts
var import_util_base64 = __nccwpck_require__(5600);
var streamCollector = /* @__PURE__ */ __name((stream) => {
  if (typeof Blob === "function" && stream instanceof Blob) {
    return collectBlob(stream);
  }
  return collectStream(stream);
}, "streamCollector");
async function collectBlob(blob) {
  const base64 = await readToBase64(blob);
  const arrayBuffer = (0, import_util_base64.fromBase64)(base64);
  return new Uint8Array(arrayBuffer);
}
__name(collectBlob, "collectBlob");
async function collectStream(stream) {
  const chunks = [];
  const reader = stream.getReader();
  let isDone = false;
  let length = 0;
  while (!isDone) {
    const { done, value } = await reader.read();
    if (value) {
      chunks.push(value);
      length += value.length;
    }
    isDone = done;
  }
  const collected = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    collected.set(chunk, offset);
    offset += chunk.length;
  }
  return collected;
}
__name(collectStream, "collectStream");
function readToBase64(blob) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onloadend = () => {
      if (reader.readyState !== 2) {
        return reject(new Error("Reader aborted too early"));
      }
      const result = reader.result ?? "";
      const commaIndex = result.indexOf(",");
      const dataOffset = commaIndex > -1 ? commaIndex + 1 : result.length;
      resolve(result.substring(dataOffset));
    };
    reader.onabort = () => reject(new Error("Read aborted"));
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(blob);
  });
}
__name(readToBase64, "readToBase64");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 3081:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  Hash: () => Hash
});
module.exports = __toCommonJS(src_exports);
var import_util_buffer_from = __nccwpck_require__(1381);
var import_util_utf8 = __nccwpck_require__(1895);
var import_buffer = __nccwpck_require__(4300);
var import_crypto = __nccwpck_require__(6113);
var _Hash = class _Hash {
  constructor(algorithmIdentifier, secret) {
    this.algorithmIdentifier = algorithmIdentifier;
    this.secret = secret;
    this.reset();
  }
  update(toHash, encoding) {
    this.hash.update((0, import_util_utf8.toUint8Array)(castSourceData(toHash, encoding)));
  }
  digest() {
    return Promise.resolve(this.hash.digest());
  }
  reset() {
    this.hash = this.secret ? (0, import_crypto.createHmac)(this.algorithmIdentifier, castSourceData(this.secret)) : (0, import_crypto.createHash)(this.algorithmIdentifier);
  }
};
__name(_Hash, "Hash");
var Hash = _Hash;
function castSourceData(toCast, encoding) {
  if (import_buffer.Buffer.isBuffer(toCast)) {
    return toCast;
  }
  if (typeof toCast === "string") {
    return (0, import_util_buffer_from.fromString)(toCast, encoding);
  }
  if (ArrayBuffer.isView(toCast)) {
    return (0, import_util_buffer_from.fromArrayBuffer)(toCast.buffer, toCast.byteOffset, toCast.byteLength);
  }
  return (0, import_util_buffer_from.fromArrayBuffer)(toCast);
}
__name(castSourceData, "castSourceData");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 780:
/***/ ((module) => {

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  isArrayBuffer: () => isArrayBuffer
});
module.exports = __toCommonJS(src_exports);
var isArrayBuffer = /* @__PURE__ */ __name((arg) => typeof ArrayBuffer === "function" && arg instanceof ArrayBuffer || Object.prototype.toString.call(arg) === "[object ArrayBuffer]", "isArrayBuffer");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 2800:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  contentLengthMiddleware: () => contentLengthMiddleware,
  contentLengthMiddlewareOptions: () => contentLengthMiddlewareOptions,
  getContentLengthPlugin: () => getContentLengthPlugin
});
module.exports = __toCommonJS(src_exports);
var import_protocol_http = __nccwpck_require__(4418);
var CONTENT_LENGTH_HEADER = "content-length";
function contentLengthMiddleware(bodyLengthChecker) {
  return (next) => async (args) => {
    const request = args.request;
    if (import_protocol_http.HttpRequest.isInstance(request)) {
      const { body, headers } = request;
      if (body && Object.keys(headers).map((str) => str.toLowerCase()).indexOf(CONTENT_LENGTH_HEADER) === -1) {
        try {
          const length = bodyLengthChecker(body);
          request.headers = {
            ...request.headers,
            [CONTENT_LENGTH_HEADER]: String(length)
          };
        } catch (error) {
        }
      }
    }
    return next({
      ...args,
      request
    });
  };
}
__name(contentLengthMiddleware, "contentLengthMiddleware");
var contentLengthMiddlewareOptions = {
  step: "build",
  tags: ["SET_CONTENT_LENGTH", "CONTENT_LENGTH"],
  name: "contentLengthMiddleware",
  override: true
};
var getContentLengthPlugin = /* @__PURE__ */ __name((options) => ({
  applyToStack: (clientStack) => {
    clientStack.add(contentLengthMiddleware(options.bodyLengthChecker), contentLengthMiddlewareOptions);
  }
}), "getContentLengthPlugin");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 1518:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.getEndpointFromConfig = void 0;
const node_config_provider_1 = __nccwpck_require__(3461);
const getEndpointUrlConfig_1 = __nccwpck_require__(7574);
const getEndpointFromConfig = async (serviceId) => (0, node_config_provider_1.loadConfig)((0, getEndpointUrlConfig_1.getEndpointUrlConfig)(serviceId))();
exports.getEndpointFromConfig = getEndpointFromConfig;


/***/ }),

/***/ 7574:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.getEndpointUrlConfig = void 0;
const shared_ini_file_loader_1 = __nccwpck_require__(3507);
const ENV_ENDPOINT_URL = "AWS_ENDPOINT_URL";
const CONFIG_ENDPOINT_URL = "endpoint_url";
const getEndpointUrlConfig = (serviceId) => ({
    environmentVariableSelector: (env) => {
        const serviceSuffixParts = serviceId.split(" ").map((w) => w.toUpperCase());
        const serviceEndpointUrl = env[[ENV_ENDPOINT_URL, ...serviceSuffixParts].join("_")];
        if (serviceEndpointUrl)
            return serviceEndpointUrl;
        const endpointUrl = env[ENV_ENDPOINT_URL];
        if (endpointUrl)
            return endpointUrl;
        return undefined;
    },
    configFileSelector: (profile, config) => {
        if (config && profile.services) {
            const servicesSection = config[["services", profile.services].join(shared_ini_file_loader_1.CONFIG_PREFIX_SEPARATOR)];
            if (servicesSection) {
                const servicePrefixParts = serviceId.split(" ").map((w) => w.toLowerCase());
                const endpointUrl = servicesSection[[servicePrefixParts.join("_"), CONFIG_ENDPOINT_URL].join(shared_ini_file_loader_1.CONFIG_PREFIX_SEPARATOR)];
                if (endpointUrl)
                    return endpointUrl;
            }
        }
        const endpointUrl = profile[CONFIG_ENDPOINT_URL];
        if (endpointUrl)
            return endpointUrl;
        return undefined;
    },
    default: undefined,
});
exports.getEndpointUrlConfig = getEndpointUrlConfig;


/***/ }),

/***/ 2918:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  endpointMiddleware: () => endpointMiddleware,
  endpointMiddlewareOptions: () => endpointMiddlewareOptions,
  getEndpointFromInstructions: () => getEndpointFromInstructions,
  getEndpointPlugin: () => getEndpointPlugin,
  resolveEndpointConfig: () => resolveEndpointConfig,
  resolveParams: () => resolveParams,
  toEndpointV1: () => toEndpointV1
});
module.exports = __toCommonJS(src_exports);

// src/service-customizations/s3.ts
var resolveParamsForS3 = /* @__PURE__ */ __name(async (endpointParams) => {
  const bucket = (endpointParams == null ? void 0 : endpointParams.Bucket) || "";
  if (typeof endpointParams.Bucket === "string") {
    endpointParams.Bucket = bucket.replace(/#/g, encodeURIComponent("#")).replace(/\?/g, encodeURIComponent("?"));
  }
  if (isArnBucketName(bucket)) {
    if (endpointParams.ForcePathStyle === true) {
      throw new Error("Path-style addressing cannot be used with ARN buckets");
    }
  } else if (!isDnsCompatibleBucketName(bucket) || bucket.indexOf(".") !== -1 && !String(endpointParams.Endpoint).startsWith("http:") || bucket.toLowerCase() !== bucket || bucket.length < 3) {
    endpointParams.ForcePathStyle = true;
  }
  if (endpointParams.DisableMultiRegionAccessPoints) {
    endpointParams.disableMultiRegionAccessPoints = true;
    endpointParams.DisableMRAP = true;
  }
  return endpointParams;
}, "resolveParamsForS3");
var DOMAIN_PATTERN = /^[a-z0-9][a-z0-9\.\-]{1,61}[a-z0-9]$/;
var IP_ADDRESS_PATTERN = /(\d+\.){3}\d+/;
var DOTS_PATTERN = /\.\./;
var isDnsCompatibleBucketName = /* @__PURE__ */ __name((bucketName) => DOMAIN_PATTERN.test(bucketName) && !IP_ADDRESS_PATTERN.test(bucketName) && !DOTS_PATTERN.test(bucketName), "isDnsCompatibleBucketName");
var isArnBucketName = /* @__PURE__ */ __name((bucketName) => {
  const [arn, partition, service, , , bucket] = bucketName.split(":");
  const isArn = arn === "arn" && bucketName.split(":").length >= 6;
  const isValidArn = Boolean(isArn && partition && service && bucket);
  if (isArn && !isValidArn) {
    throw new Error(`Invalid ARN: ${bucketName} was an invalid ARN.`);
  }
  return isValidArn;
}, "isArnBucketName");

// src/adaptors/createConfigValueProvider.ts
var createConfigValueProvider = /* @__PURE__ */ __name((configKey, canonicalEndpointParamKey, config) => {
  const configProvider = /* @__PURE__ */ __name(async () => {
    const configValue = config[configKey] ?? config[canonicalEndpointParamKey];
    if (typeof configValue === "function") {
      return configValue();
    }
    return configValue;
  }, "configProvider");
  if (configKey === "credentialScope" || canonicalEndpointParamKey === "CredentialScope") {
    return async () => {
      const credentials = typeof config.credentials === "function" ? await config.credentials() : config.credentials;
      const configValue = (credentials == null ? void 0 : credentials.credentialScope) ?? (credentials == null ? void 0 : credentials.CredentialScope);
      return configValue;
    };
  }
  if (configKey === "accountId" || canonicalEndpointParamKey === "AccountId") {
    return async () => {
      const credentials = typeof config.credentials === "function" ? await config.credentials() : config.credentials;
      const configValue = (credentials == null ? void 0 : credentials.accountId) ?? (credentials == null ? void 0 : credentials.AccountId);
      return configValue;
    };
  }
  if (configKey === "endpoint" || canonicalEndpointParamKey === "endpoint") {
    return async () => {
      const endpoint = await configProvider();
      if (endpoint && typeof endpoint === "object") {
        if ("url" in endpoint) {
          return endpoint.url.href;
        }
        if ("hostname" in endpoint) {
          const { protocol, hostname, port, path } = endpoint;
          return `${protocol}//${hostname}${port ? ":" + port : ""}${path}`;
        }
      }
      return endpoint;
    };
  }
  return configProvider;
}, "createConfigValueProvider");

// src/adaptors/getEndpointFromInstructions.ts
var import_getEndpointFromConfig = __nccwpck_require__(1518);

// src/adaptors/toEndpointV1.ts
var import_url_parser = __nccwpck_require__(4681);
var toEndpointV1 = /* @__PURE__ */ __name((endpoint) => {
  if (typeof endpoint === "object") {
    if ("url" in endpoint) {
      return (0, import_url_parser.parseUrl)(endpoint.url);
    }
    return endpoint;
  }
  return (0, import_url_parser.parseUrl)(endpoint);
}, "toEndpointV1");

// src/adaptors/getEndpointFromInstructions.ts
var getEndpointFromInstructions = /* @__PURE__ */ __name(async (commandInput, instructionsSupplier, clientConfig, context) => {
  if (!clientConfig.endpoint) {
    const endpointFromConfig = await (0, import_getEndpointFromConfig.getEndpointFromConfig)(clientConfig.serviceId || "");
    if (endpointFromConfig) {
      clientConfig.endpoint = () => Promise.resolve(toEndpointV1(endpointFromConfig));
    }
  }
  const endpointParams = await resolveParams(commandInput, instructionsSupplier, clientConfig);
  if (typeof clientConfig.endpointProvider !== "function") {
    throw new Error("config.endpointProvider is not set.");
  }
  const endpoint = clientConfig.endpointProvider(endpointParams, context);
  return endpoint;
}, "getEndpointFromInstructions");
var resolveParams = /* @__PURE__ */ __name(async (commandInput, instructionsSupplier, clientConfig) => {
  var _a;
  const endpointParams = {};
  const instructions = ((_a = instructionsSupplier == null ? void 0 : instructionsSupplier.getEndpointParameterInstructions) == null ? void 0 : _a.call(instructionsSupplier)) || {};
  for (const [name, instruction] of Object.entries(instructions)) {
    switch (instruction.type) {
      case "staticContextParams":
        endpointParams[name] = instruction.value;
        break;
      case "contextParams":
        endpointParams[name] = commandInput[instruction.name];
        break;
      case "clientContextParams":
      case "builtInParams":
        endpointParams[name] = await createConfigValueProvider(instruction.name, name, clientConfig)();
        break;
      default:
        throw new Error("Unrecognized endpoint parameter instruction: " + JSON.stringify(instruction));
    }
  }
  if (Object.keys(instructions).length === 0) {
    Object.assign(endpointParams, clientConfig);
  }
  if (String(clientConfig.serviceId).toLowerCase() === "s3") {
    await resolveParamsForS3(endpointParams);
  }
  return endpointParams;
}, "resolveParams");

// src/endpointMiddleware.ts
var import_util_middleware = __nccwpck_require__(2390);
var endpointMiddleware = /* @__PURE__ */ __name(({
  config,
  instructions
}) => {
  return (next, context) => async (args) => {
    var _a, _b, _c;
    const endpoint = await getEndpointFromInstructions(
      args.input,
      {
        getEndpointParameterInstructions() {
          return instructions;
        }
      },
      { ...config },
      context
    );
    context.endpointV2 = endpoint;
    context.authSchemes = (_a = endpoint.properties) == null ? void 0 : _a.authSchemes;
    const authScheme = (_b = context.authSchemes) == null ? void 0 : _b[0];
    if (authScheme) {
      context["signing_region"] = authScheme.signingRegion;
      context["signing_service"] = authScheme.signingName;
      const smithyContext = (0, import_util_middleware.getSmithyContext)(context);
      const httpAuthOption = (_c = smithyContext == null ? void 0 : smithyContext.selectedHttpAuthScheme) == null ? void 0 : _c.httpAuthOption;
      if (httpAuthOption) {
        httpAuthOption.signingProperties = Object.assign(
          httpAuthOption.signingProperties || {},
          {
            signing_region: authScheme.signingRegion,
            signingRegion: authScheme.signingRegion,
            signing_service: authScheme.signingName,
            signingName: authScheme.signingName,
            signingRegionSet: authScheme.signingRegionSet
          },
          authScheme.properties
        );
      }
    }
    return next({
      ...args
    });
  };
}, "endpointMiddleware");

// src/getEndpointPlugin.ts
var import_middleware_serde = __nccwpck_require__(1238);
var endpointMiddlewareOptions = {
  step: "serialize",
  tags: ["ENDPOINT_PARAMETERS", "ENDPOINT_V2", "ENDPOINT"],
  name: "endpointV2Middleware",
  override: true,
  relation: "before",
  toMiddleware: import_middleware_serde.serializerMiddlewareOption.name
};
var getEndpointPlugin = /* @__PURE__ */ __name((config, instructions) => ({
  applyToStack: (clientStack) => {
    clientStack.addRelativeTo(
      endpointMiddleware({
        config,
        instructions
      }),
      endpointMiddlewareOptions
    );
  }
}), "getEndpointPlugin");

// src/resolveEndpointConfig.ts

var resolveEndpointConfig = /* @__PURE__ */ __name((input) => {
  const tls = input.tls ?? true;
  const { endpoint } = input;
  const customEndpointProvider = endpoint != null ? async () => toEndpointV1(await (0, import_util_middleware.normalizeProvider)(endpoint)()) : void 0;
  const isCustomEndpoint = !!endpoint;
  return {
    ...input,
    endpoint: customEndpointProvider,
    tls,
    isCustomEndpoint,
    useDualstackEndpoint: (0, import_util_middleware.normalizeProvider)(input.useDualstackEndpoint ?? false),
    useFipsEndpoint: (0, import_util_middleware.normalizeProvider)(input.useFipsEndpoint ?? false)
  };
}, "resolveEndpointConfig");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 6039:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  AdaptiveRetryStrategy: () => AdaptiveRetryStrategy,
  CONFIG_MAX_ATTEMPTS: () => CONFIG_MAX_ATTEMPTS,
  CONFIG_RETRY_MODE: () => CONFIG_RETRY_MODE,
  ENV_MAX_ATTEMPTS: () => ENV_MAX_ATTEMPTS,
  ENV_RETRY_MODE: () => ENV_RETRY_MODE,
  NODE_MAX_ATTEMPT_CONFIG_OPTIONS: () => NODE_MAX_ATTEMPT_CONFIG_OPTIONS,
  NODE_RETRY_MODE_CONFIG_OPTIONS: () => NODE_RETRY_MODE_CONFIG_OPTIONS,
  StandardRetryStrategy: () => StandardRetryStrategy,
  defaultDelayDecider: () => defaultDelayDecider,
  defaultRetryDecider: () => defaultRetryDecider,
  getOmitRetryHeadersPlugin: () => getOmitRetryHeadersPlugin,
  getRetryAfterHint: () => getRetryAfterHint,
  getRetryPlugin: () => getRetryPlugin,
  omitRetryHeadersMiddleware: () => omitRetryHeadersMiddleware,
  omitRetryHeadersMiddlewareOptions: () => omitRetryHeadersMiddlewareOptions,
  resolveRetryConfig: () => resolveRetryConfig,
  retryMiddleware: () => retryMiddleware,
  retryMiddlewareOptions: () => retryMiddlewareOptions
});
module.exports = __toCommonJS(src_exports);

// src/AdaptiveRetryStrategy.ts


// src/StandardRetryStrategy.ts
var import_protocol_http = __nccwpck_require__(4418);


var import_uuid = __nccwpck_require__(7761);

// src/defaultRetryQuota.ts
var import_util_retry = __nccwpck_require__(4902);
var getDefaultRetryQuota = /* @__PURE__ */ __name((initialRetryTokens, options) => {
  const MAX_CAPACITY = initialRetryTokens;
  const noRetryIncrement = (options == null ? void 0 : options.noRetryIncrement) ?? import_util_retry.NO_RETRY_INCREMENT;
  const retryCost = (options == null ? void 0 : options.retryCost) ?? import_util_retry.RETRY_COST;
  const timeoutRetryCost = (options == null ? void 0 : options.timeoutRetryCost) ?? import_util_retry.TIMEOUT_RETRY_COST;
  let availableCapacity = initialRetryTokens;
  const getCapacityAmount = /* @__PURE__ */ __name((error) => error.name === "TimeoutError" ? timeoutRetryCost : retryCost, "getCapacityAmount");
  const hasRetryTokens = /* @__PURE__ */ __name((error) => getCapacityAmount(error) <= availableCapacity, "hasRetryTokens");
  const retrieveRetryTokens = /* @__PURE__ */ __name((error) => {
    if (!hasRetryTokens(error)) {
      throw new Error("No retry token available");
    }
    const capacityAmount = getCapacityAmount(error);
    availableCapacity -= capacityAmount;
    return capacityAmount;
  }, "retrieveRetryTokens");
  const releaseRetryTokens = /* @__PURE__ */ __name((capacityReleaseAmount) => {
    availableCapacity += capacityReleaseAmount ?? noRetryIncrement;
    availableCapacity = Math.min(availableCapacity, MAX_CAPACITY);
  }, "releaseRetryTokens");
  return Object.freeze({
    hasRetryTokens,
    retrieveRetryTokens,
    releaseRetryTokens
  });
}, "getDefaultRetryQuota");

// src/delayDecider.ts

var defaultDelayDecider = /* @__PURE__ */ __name((delayBase, attempts) => Math.floor(Math.min(import_util_retry.MAXIMUM_RETRY_DELAY, Math.random() * 2 ** attempts * delayBase)), "defaultDelayDecider");

// src/retryDecider.ts
var import_service_error_classification = __nccwpck_require__(6375);
var defaultRetryDecider = /* @__PURE__ */ __name((error) => {
  if (!error) {
    return false;
  }
  return (0, import_service_error_classification.isRetryableByTrait)(error) || (0, import_service_error_classification.isClockSkewError)(error) || (0, import_service_error_classification.isThrottlingError)(error) || (0, import_service_error_classification.isTransientError)(error);
}, "defaultRetryDecider");

// src/util.ts
var asSdkError = /* @__PURE__ */ __name((error) => {
  if (error instanceof Error)
    return error;
  if (error instanceof Object)
    return Object.assign(new Error(), error);
  if (typeof error === "string")
    return new Error(error);
  return new Error(`AWS SDK error wrapper for ${error}`);
}, "asSdkError");

// src/StandardRetryStrategy.ts
var _StandardRetryStrategy = class _StandardRetryStrategy {
  constructor(maxAttemptsProvider, options) {
    this.maxAttemptsProvider = maxAttemptsProvider;
    this.mode = import_util_retry.RETRY_MODES.STANDARD;
    this.retryDecider = (options == null ? void 0 : options.retryDecider) ?? defaultRetryDecider;
    this.delayDecider = (options == null ? void 0 : options.delayDecider) ?? defaultDelayDecider;
    this.retryQuota = (options == null ? void 0 : options.retryQuota) ?? getDefaultRetryQuota(import_util_retry.INITIAL_RETRY_TOKENS);
  }
  shouldRetry(error, attempts, maxAttempts) {
    return attempts < maxAttempts && this.retryDecider(error) && this.retryQuota.hasRetryTokens(error);
  }
  async getMaxAttempts() {
    let maxAttempts;
    try {
      maxAttempts = await this.maxAttemptsProvider();
    } catch (error) {
      maxAttempts = import_util_retry.DEFAULT_MAX_ATTEMPTS;
    }
    return maxAttempts;
  }
  async retry(next, args, options) {
    let retryTokenAmount;
    let attempts = 0;
    let totalDelay = 0;
    const maxAttempts = await this.getMaxAttempts();
    const { request } = args;
    if (import_protocol_http.HttpRequest.isInstance(request)) {
      request.headers[import_util_retry.INVOCATION_ID_HEADER] = (0, import_uuid.v4)();
    }
    while (true) {
      try {
        if (import_protocol_http.HttpRequest.isInstance(request)) {
          request.headers[import_util_retry.REQUEST_HEADER] = `attempt=${attempts + 1}; max=${maxAttempts}`;
        }
        if (options == null ? void 0 : options.beforeRequest) {
          await options.beforeRequest();
        }
        const { response, output } = await next(args);
        if (options == null ? void 0 : options.afterRequest) {
          options.afterRequest(response);
        }
        this.retryQuota.releaseRetryTokens(retryTokenAmount);
        output.$metadata.attempts = attempts + 1;
        output.$metadata.totalRetryDelay = totalDelay;
        return { response, output };
      } catch (e) {
        const err = asSdkError(e);
        attempts++;
        if (this.shouldRetry(err, attempts, maxAttempts)) {
          retryTokenAmount = this.retryQuota.retrieveRetryTokens(err);
          const delayFromDecider = this.delayDecider(
            (0, import_service_error_classification.isThrottlingError)(err) ? import_util_retry.THROTTLING_RETRY_DELAY_BASE : import_util_retry.DEFAULT_RETRY_DELAY_BASE,
            attempts
          );
          const delayFromResponse = getDelayFromRetryAfterHeader(err.$response);
          const delay = Math.max(delayFromResponse || 0, delayFromDecider);
          totalDelay += delay;
          await new Promise((resolve) => setTimeout(resolve, delay));
          continue;
        }
        if (!err.$metadata) {
          err.$metadata = {};
        }
        err.$metadata.attempts = attempts;
        err.$metadata.totalRetryDelay = totalDelay;
        throw err;
      }
    }
  }
};
__name(_StandardRetryStrategy, "StandardRetryStrategy");
var StandardRetryStrategy = _StandardRetryStrategy;
var getDelayFromRetryAfterHeader = /* @__PURE__ */ __name((response) => {
  if (!import_protocol_http.HttpResponse.isInstance(response))
    return;
  const retryAfterHeaderName = Object.keys(response.headers).find((key) => key.toLowerCase() === "retry-after");
  if (!retryAfterHeaderName)
    return;
  const retryAfter = response.headers[retryAfterHeaderName];
  const retryAfterSeconds = Number(retryAfter);
  if (!Number.isNaN(retryAfterSeconds))
    return retryAfterSeconds * 1e3;
  const retryAfterDate = new Date(retryAfter);
  return retryAfterDate.getTime() - Date.now();
}, "getDelayFromRetryAfterHeader");

// src/AdaptiveRetryStrategy.ts
var _AdaptiveRetryStrategy = class _AdaptiveRetryStrategy extends StandardRetryStrategy {
  constructor(maxAttemptsProvider, options) {
    const { rateLimiter, ...superOptions } = options ?? {};
    super(maxAttemptsProvider, superOptions);
    this.rateLimiter = rateLimiter ?? new import_util_retry.DefaultRateLimiter();
    this.mode = import_util_retry.RETRY_MODES.ADAPTIVE;
  }
  async retry(next, args) {
    return super.retry(next, args, {
      beforeRequest: async () => {
        return this.rateLimiter.getSendToken();
      },
      afterRequest: (response) => {
        this.rateLimiter.updateClientSendingRate(response);
      }
    });
  }
};
__name(_AdaptiveRetryStrategy, "AdaptiveRetryStrategy");
var AdaptiveRetryStrategy = _AdaptiveRetryStrategy;

// src/configurations.ts
var import_util_middleware = __nccwpck_require__(2390);

var ENV_MAX_ATTEMPTS = "AWS_MAX_ATTEMPTS";
var CONFIG_MAX_ATTEMPTS = "max_attempts";
var NODE_MAX_ATTEMPT_CONFIG_OPTIONS = {
  environmentVariableSelector: (env) => {
    const value = env[ENV_MAX_ATTEMPTS];
    if (!value)
      return void 0;
    const maxAttempt = parseInt(value);
    if (Number.isNaN(maxAttempt)) {
      throw new Error(`Environment variable ${ENV_MAX_ATTEMPTS} mast be a number, got "${value}"`);
    }
    return maxAttempt;
  },
  configFileSelector: (profile) => {
    const value = profile[CONFIG_MAX_ATTEMPTS];
    if (!value)
      return void 0;
    const maxAttempt = parseInt(value);
    if (Number.isNaN(maxAttempt)) {
      throw new Error(`Shared config file entry ${CONFIG_MAX_ATTEMPTS} mast be a number, got "${value}"`);
    }
    return maxAttempt;
  },
  default: import_util_retry.DEFAULT_MAX_ATTEMPTS
};
var resolveRetryConfig = /* @__PURE__ */ __name((input) => {
  const { retryStrategy } = input;
  const maxAttempts = (0, import_util_middleware.normalizeProvider)(input.maxAttempts ?? import_util_retry.DEFAULT_MAX_ATTEMPTS);
  return {
    ...input,
    maxAttempts,
    retryStrategy: async () => {
      if (retryStrategy) {
        return retryStrategy;
      }
      const retryMode = await (0, import_util_middleware.normalizeProvider)(input.retryMode)();
      if (retryMode === import_util_retry.RETRY_MODES.ADAPTIVE) {
        return new import_util_retry.AdaptiveRetryStrategy(maxAttempts);
      }
      return new import_util_retry.StandardRetryStrategy(maxAttempts);
    }
  };
}, "resolveRetryConfig");
var ENV_RETRY_MODE = "AWS_RETRY_MODE";
var CONFIG_RETRY_MODE = "retry_mode";
var NODE_RETRY_MODE_CONFIG_OPTIONS = {
  environmentVariableSelector: (env) => env[ENV_RETRY_MODE],
  configFileSelector: (profile) => profile[CONFIG_RETRY_MODE],
  default: import_util_retry.DEFAULT_RETRY_MODE
};

// src/omitRetryHeadersMiddleware.ts


var omitRetryHeadersMiddleware = /* @__PURE__ */ __name(() => (next) => async (args) => {
  const { request } = args;
  if (import_protocol_http.HttpRequest.isInstance(request)) {
    delete request.headers[import_util_retry.INVOCATION_ID_HEADER];
    delete request.headers[import_util_retry.REQUEST_HEADER];
  }
  return next(args);
}, "omitRetryHeadersMiddleware");
var omitRetryHeadersMiddlewareOptions = {
  name: "omitRetryHeadersMiddleware",
  tags: ["RETRY", "HEADERS", "OMIT_RETRY_HEADERS"],
  relation: "before",
  toMiddleware: "awsAuthMiddleware",
  override: true
};
var getOmitRetryHeadersPlugin = /* @__PURE__ */ __name((options) => ({
  applyToStack: (clientStack) => {
    clientStack.addRelativeTo(omitRetryHeadersMiddleware(), omitRetryHeadersMiddlewareOptions);
  }
}), "getOmitRetryHeadersPlugin");

// src/retryMiddleware.ts


var import_smithy_client = __nccwpck_require__(3570);


var import_isStreamingPayload = __nccwpck_require__(8977);
var retryMiddleware = /* @__PURE__ */ __name((options) => (next, context) => async (args) => {
  var _a;
  let retryStrategy = await options.retryStrategy();
  const maxAttempts = await options.maxAttempts();
  if (isRetryStrategyV2(retryStrategy)) {
    retryStrategy = retryStrategy;
    let retryToken = await retryStrategy.acquireInitialRetryToken(context["partition_id"]);
    let lastError = new Error();
    let attempts = 0;
    let totalRetryDelay = 0;
    const { request } = args;
    const isRequest = import_protocol_http.HttpRequest.isInstance(request);
    if (isRequest) {
      request.headers[import_util_retry.INVOCATION_ID_HEADER] = (0, import_uuid.v4)();
    }
    while (true) {
      try {
        if (isRequest) {
          request.headers[import_util_retry.REQUEST_HEADER] = `attempt=${attempts + 1}; max=${maxAttempts}`;
        }
        const { response, output } = await next(args);
        retryStrategy.recordSuccess(retryToken);
        output.$metadata.attempts = attempts + 1;
        output.$metadata.totalRetryDelay = totalRetryDelay;
        return { response, output };
      } catch (e) {
        const retryErrorInfo = getRetryErrorInfo(e);
        lastError = asSdkError(e);
        if (isRequest && (0, import_isStreamingPayload.isStreamingPayload)(request)) {
          (_a = context.logger instanceof import_smithy_client.NoOpLogger ? console : context.logger) == null ? void 0 : _a.warn(
            "An error was encountered in a non-retryable streaming request."
          );
          throw lastError;
        }
        try {
          retryToken = await retryStrategy.refreshRetryTokenForRetry(retryToken, retryErrorInfo);
        } catch (refreshError) {
          if (!lastError.$metadata) {
            lastError.$metadata = {};
          }
          lastError.$metadata.attempts = attempts + 1;
          lastError.$metadata.totalRetryDelay = totalRetryDelay;
          throw lastError;
        }
        attempts = retryToken.getRetryCount();
        const delay = retryToken.getRetryDelay();
        totalRetryDelay += delay;
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }
  } else {
    retryStrategy = retryStrategy;
    if (retryStrategy == null ? void 0 : retryStrategy.mode)
      context.userAgent = [...context.userAgent || [], ["cfg/retry-mode", retryStrategy.mode]];
    return retryStrategy.retry(next, args);
  }
}, "retryMiddleware");
var isRetryStrategyV2 = /* @__PURE__ */ __name((retryStrategy) => typeof retryStrategy.acquireInitialRetryToken !== "undefined" && typeof retryStrategy.refreshRetryTokenForRetry !== "undefined" && typeof retryStrategy.recordSuccess !== "undefined", "isRetryStrategyV2");
var getRetryErrorInfo = /* @__PURE__ */ __name((error) => {
  const errorInfo = {
    error,
    errorType: getRetryErrorType(error)
  };
  const retryAfterHint = getRetryAfterHint(error.$response);
  if (retryAfterHint) {
    errorInfo.retryAfterHint = retryAfterHint;
  }
  return errorInfo;
}, "getRetryErrorInfo");
var getRetryErrorType = /* @__PURE__ */ __name((error) => {
  if ((0, import_service_error_classification.isThrottlingError)(error))
    return "THROTTLING";
  if ((0, import_service_error_classification.isTransientError)(error))
    return "TRANSIENT";
  if ((0, import_service_error_classification.isServerError)(error))
    return "SERVER_ERROR";
  return "CLIENT_ERROR";
}, "getRetryErrorType");
var retryMiddlewareOptions = {
  name: "retryMiddleware",
  tags: ["RETRY"],
  step: "finalizeRequest",
  priority: "high",
  override: true
};
var getRetryPlugin = /* @__PURE__ */ __name((options) => ({
  applyToStack: (clientStack) => {
    clientStack.add(retryMiddleware(options), retryMiddlewareOptions);
  }
}), "getRetryPlugin");
var getRetryAfterHint = /* @__PURE__ */ __name((response) => {
  if (!import_protocol_http.HttpResponse.isInstance(response))
    return;
  const retryAfterHeaderName = Object.keys(response.headers).find((key) => key.toLowerCase() === "retry-after");
  if (!retryAfterHeaderName)
    return;
  const retryAfter = response.headers[retryAfterHeaderName];
  const retryAfterSeconds = Number(retryAfter);
  if (!Number.isNaN(retryAfterSeconds))
    return new Date(retryAfterSeconds * 1e3);
  const retryAfterDate = new Date(retryAfter);
  return retryAfterDate;
}, "getRetryAfterHint");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 8977:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.isStreamingPayload = void 0;
const stream_1 = __nccwpck_require__(2781);
const isStreamingPayload = (request) => (request === null || request === void 0 ? void 0 : request.body) instanceof stream_1.Readable ||
    (typeof ReadableStream !== "undefined" && (request === null || request === void 0 ? void 0 : request.body) instanceof ReadableStream);
exports.isStreamingPayload = isStreamingPayload;


/***/ }),

/***/ 7761:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
Object.defineProperty(exports, "NIL", ({
  enumerable: true,
  get: function () {
    return _nil.default;
  }
}));
Object.defineProperty(exports, "parse", ({
  enumerable: true,
  get: function () {
    return _parse.default;
  }
}));
Object.defineProperty(exports, "stringify", ({
  enumerable: true,
  get: function () {
    return _stringify.default;
  }
}));
Object.defineProperty(exports, "v1", ({
  enumerable: true,
  get: function () {
    return _v.default;
  }
}));
Object.defineProperty(exports, "v3", ({
  enumerable: true,
  get: function () {
    return _v2.default;
  }
}));
Object.defineProperty(exports, "v4", ({
  enumerable: true,
  get: function () {
    return _v3.default;
  }
}));
Object.defineProperty(exports, "v5", ({
  enumerable: true,
  get: function () {
    return _v4.default;
  }
}));
Object.defineProperty(exports, "validate", ({
  enumerable: true,
  get: function () {
    return _validate.default;
  }
}));
Object.defineProperty(exports, "version", ({
  enumerable: true,
  get: function () {
    return _version.default;
  }
}));

var _v = _interopRequireDefault(__nccwpck_require__(6310));

var _v2 = _interopRequireDefault(__nccwpck_require__(9465));

var _v3 = _interopRequireDefault(__nccwpck_require__(6001));

var _v4 = _interopRequireDefault(__nccwpck_require__(8310));

var _nil = _interopRequireDefault(__nccwpck_require__(3436));

var _version = _interopRequireDefault(__nccwpck_require__(7780));

var _validate = _interopRequireDefault(__nccwpck_require__(6992));

var _stringify = _interopRequireDefault(__nccwpck_require__(9618));

var _parse = _interopRequireDefault(__nccwpck_require__(86));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/***/ }),

/***/ 1380:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _crypto = _interopRequireDefault(__nccwpck_require__(6113));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function md5(bytes) {
  if (Array.isArray(bytes)) {
    bytes = Buffer.from(bytes);
  } else if (typeof bytes === 'string') {
    bytes = Buffer.from(bytes, 'utf8');
  }

  return _crypto.default.createHash('md5').update(bytes).digest();
}

var _default = md5;
exports["default"] = _default;

/***/ }),

/***/ 4672:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _crypto = _interopRequireDefault(__nccwpck_require__(6113));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var _default = {
  randomUUID: _crypto.default.randomUUID
};
exports["default"] = _default;

/***/ }),

/***/ 3436:
/***/ ((__unused_webpack_module, exports) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;
var _default = '00000000-0000-0000-0000-000000000000';
exports["default"] = _default;

/***/ }),

/***/ 86:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _validate = _interopRequireDefault(__nccwpck_require__(6992));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function parse(uuid) {
  if (!(0, _validate.default)(uuid)) {
    throw TypeError('Invalid UUID');
  }

  let v;
  const arr = new Uint8Array(16); // Parse ########-....-....-....-............

  arr[0] = (v = parseInt(uuid.slice(0, 8), 16)) >>> 24;
  arr[1] = v >>> 16 & 0xff;
  arr[2] = v >>> 8 & 0xff;
  arr[3] = v & 0xff; // Parse ........-####-....-....-............

  arr[4] = (v = parseInt(uuid.slice(9, 13), 16)) >>> 8;
  arr[5] = v & 0xff; // Parse ........-....-####-....-............

  arr[6] = (v = parseInt(uuid.slice(14, 18), 16)) >>> 8;
  arr[7] = v & 0xff; // Parse ........-....-....-####-............

  arr[8] = (v = parseInt(uuid.slice(19, 23), 16)) >>> 8;
  arr[9] = v & 0xff; // Parse ........-....-....-....-############
  // (Use "/" to avoid 32-bit truncation when bit-shifting high-order bytes)

  arr[10] = (v = parseInt(uuid.slice(24, 36), 16)) / 0x10000000000 & 0xff;
  arr[11] = v / 0x100000000 & 0xff;
  arr[12] = v >>> 24 & 0xff;
  arr[13] = v >>> 16 & 0xff;
  arr[14] = v >>> 8 & 0xff;
  arr[15] = v & 0xff;
  return arr;
}

var _default = parse;
exports["default"] = _default;

/***/ }),

/***/ 3194:
/***/ ((__unused_webpack_module, exports) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;
var _default = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000)$/i;
exports["default"] = _default;

/***/ }),

/***/ 8136:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = rng;

var _crypto = _interopRequireDefault(__nccwpck_require__(6113));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const rnds8Pool = new Uint8Array(256); // # of random values to pre-allocate

let poolPtr = rnds8Pool.length;

function rng() {
  if (poolPtr > rnds8Pool.length - 16) {
    _crypto.default.randomFillSync(rnds8Pool);

    poolPtr = 0;
  }

  return rnds8Pool.slice(poolPtr, poolPtr += 16);
}

/***/ }),

/***/ 6679:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _crypto = _interopRequireDefault(__nccwpck_require__(6113));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function sha1(bytes) {
  if (Array.isArray(bytes)) {
    bytes = Buffer.from(bytes);
  } else if (typeof bytes === 'string') {
    bytes = Buffer.from(bytes, 'utf8');
  }

  return _crypto.default.createHash('sha1').update(bytes).digest();
}

var _default = sha1;
exports["default"] = _default;

/***/ }),

/***/ 9618:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;
exports.unsafeStringify = unsafeStringify;

var _validate = _interopRequireDefault(__nccwpck_require__(6992));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * Convert array of 16 byte values to UUID string format of the form:
 * XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
 */
const byteToHex = [];

for (let i = 0; i < 256; ++i) {
  byteToHex.push((i + 0x100).toString(16).slice(1));
}

function unsafeStringify(arr, offset = 0) {
  // Note: Be careful editing this code!  It's been tuned for performance
  // and works in ways you may not expect. See https://github.com/uuidjs/uuid/pull/434
  return byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + '-' + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + '-' + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + '-' + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + '-' + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]];
}

function stringify(arr, offset = 0) {
  const uuid = unsafeStringify(arr, offset); // Consistency check for valid UUID.  If this throws, it's likely due to one
  // of the following:
  // - One or more input array values don't map to a hex octet (leading to
  // "undefined" in the uuid)
  // - Invalid input values for the RFC `version` or `variant` fields

  if (!(0, _validate.default)(uuid)) {
    throw TypeError('Stringified UUID is invalid');
  }

  return uuid;
}

var _default = stringify;
exports["default"] = _default;

/***/ }),

/***/ 6310:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _rng = _interopRequireDefault(__nccwpck_require__(8136));

var _stringify = __nccwpck_require__(9618);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

// **`v1()` - Generate time-based UUID**
//
// Inspired by https://github.com/LiosK/UUID.js
// and http://docs.python.org/library/uuid.html
let _nodeId;

let _clockseq; // Previous uuid creation time


let _lastMSecs = 0;
let _lastNSecs = 0; // See https://github.com/uuidjs/uuid for API details

function v1(options, buf, offset) {
  let i = buf && offset || 0;
  const b = buf || new Array(16);
  options = options || {};
  let node = options.node || _nodeId;
  let clockseq = options.clockseq !== undefined ? options.clockseq : _clockseq; // node and clockseq need to be initialized to random values if they're not
  // specified.  We do this lazily to minimize issues related to insufficient
  // system entropy.  See #189

  if (node == null || clockseq == null) {
    const seedBytes = options.random || (options.rng || _rng.default)();

    if (node == null) {
      // Per 4.5, create and 48-bit node id, (47 random bits + multicast bit = 1)
      node = _nodeId = [seedBytes[0] | 0x01, seedBytes[1], seedBytes[2], seedBytes[3], seedBytes[4], seedBytes[5]];
    }

    if (clockseq == null) {
      // Per 4.2.2, randomize (14 bit) clockseq
      clockseq = _clockseq = (seedBytes[6] << 8 | seedBytes[7]) & 0x3fff;
    }
  } // UUID timestamps are 100 nano-second units since the Gregorian epoch,
  // (1582-10-15 00:00).  JSNumbers aren't precise enough for this, so
  // time is handled internally as 'msecs' (integer milliseconds) and 'nsecs'
  // (100-nanoseconds offset from msecs) since unix epoch, 1970-01-01 00:00.


  let msecs = options.msecs !== undefined ? options.msecs : Date.now(); // Per 4.2.1.2, use count of uuid's generated during the current clock
  // cycle to simulate higher resolution clock

  let nsecs = options.nsecs !== undefined ? options.nsecs : _lastNSecs + 1; // Time since last uuid creation (in msecs)

  const dt = msecs - _lastMSecs + (nsecs - _lastNSecs) / 10000; // Per 4.2.1.2, Bump clockseq on clock regression

  if (dt < 0 && options.clockseq === undefined) {
    clockseq = clockseq + 1 & 0x3fff;
  } // Reset nsecs if clock regresses (new clockseq) or we've moved onto a new
  // time interval


  if ((dt < 0 || msecs > _lastMSecs) && options.nsecs === undefined) {
    nsecs = 0;
  } // Per 4.2.1.2 Throw error if too many uuids are requested


  if (nsecs >= 10000) {
    throw new Error("uuid.v1(): Can't create more than 10M uuids/sec");
  }

  _lastMSecs = msecs;
  _lastNSecs = nsecs;
  _clockseq = clockseq; // Per 4.1.4 - Convert from unix epoch to Gregorian epoch

  msecs += 12219292800000; // `time_low`

  const tl = ((msecs & 0xfffffff) * 10000 + nsecs) % 0x100000000;
  b[i++] = tl >>> 24 & 0xff;
  b[i++] = tl >>> 16 & 0xff;
  b[i++] = tl >>> 8 & 0xff;
  b[i++] = tl & 0xff; // `time_mid`

  const tmh = msecs / 0x100000000 * 10000 & 0xfffffff;
  b[i++] = tmh >>> 8 & 0xff;
  b[i++] = tmh & 0xff; // `time_high_and_version`

  b[i++] = tmh >>> 24 & 0xf | 0x10; // include version

  b[i++] = tmh >>> 16 & 0xff; // `clock_seq_hi_and_reserved` (Per 4.2.2 - include variant)

  b[i++] = clockseq >>> 8 | 0x80; // `clock_seq_low`

  b[i++] = clockseq & 0xff; // `node`

  for (let n = 0; n < 6; ++n) {
    b[i + n] = node[n];
  }

  return buf || (0, _stringify.unsafeStringify)(b);
}

var _default = v1;
exports["default"] = _default;

/***/ }),

/***/ 9465:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _v = _interopRequireDefault(__nccwpck_require__(2568));

var _md = _interopRequireDefault(__nccwpck_require__(1380));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const v3 = (0, _v.default)('v3', 0x30, _md.default);
var _default = v3;
exports["default"] = _default;

/***/ }),

/***/ 2568:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports.URL = exports.DNS = void 0;
exports["default"] = v35;

var _stringify = __nccwpck_require__(9618);

var _parse = _interopRequireDefault(__nccwpck_require__(86));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function stringToBytes(str) {
  str = unescape(encodeURIComponent(str)); // UTF8 escape

  const bytes = [];

  for (let i = 0; i < str.length; ++i) {
    bytes.push(str.charCodeAt(i));
  }

  return bytes;
}

const DNS = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';
exports.DNS = DNS;
const URL = '6ba7b811-9dad-11d1-80b4-00c04fd430c8';
exports.URL = URL;

function v35(name, version, hashfunc) {
  function generateUUID(value, namespace, buf, offset) {
    var _namespace;

    if (typeof value === 'string') {
      value = stringToBytes(value);
    }

    if (typeof namespace === 'string') {
      namespace = (0, _parse.default)(namespace);
    }

    if (((_namespace = namespace) === null || _namespace === void 0 ? void 0 : _namespace.length) !== 16) {
      throw TypeError('Namespace must be array-like (16 iterable integer values, 0-255)');
    } // Compute hash of namespace and value, Per 4.3
    // Future: Use spread syntax when supported on all platforms, e.g. `bytes =
    // hashfunc([...namespace, ... value])`


    let bytes = new Uint8Array(16 + value.length);
    bytes.set(namespace);
    bytes.set(value, namespace.length);
    bytes = hashfunc(bytes);
    bytes[6] = bytes[6] & 0x0f | version;
    bytes[8] = bytes[8] & 0x3f | 0x80;

    if (buf) {
      offset = offset || 0;

      for (let i = 0; i < 16; ++i) {
        buf[offset + i] = bytes[i];
      }

      return buf;
    }

    return (0, _stringify.unsafeStringify)(bytes);
  } // Function#name is not settable on some platforms (#270)


  try {
    generateUUID.name = name; // eslint-disable-next-line no-empty
  } catch (err) {} // For CommonJS default export support


  generateUUID.DNS = DNS;
  generateUUID.URL = URL;
  return generateUUID;
}

/***/ }),

/***/ 6001:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _native = _interopRequireDefault(__nccwpck_require__(4672));

var _rng = _interopRequireDefault(__nccwpck_require__(8136));

var _stringify = __nccwpck_require__(9618);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function v4(options, buf, offset) {
  if (_native.default.randomUUID && !buf && !options) {
    return _native.default.randomUUID();
  }

  options = options || {};

  const rnds = options.random || (options.rng || _rng.default)(); // Per 4.4, set bits for version and `clock_seq_hi_and_reserved`


  rnds[6] = rnds[6] & 0x0f | 0x40;
  rnds[8] = rnds[8] & 0x3f | 0x80; // Copy bytes to buffer, if provided

  if (buf) {
    offset = offset || 0;

    for (let i = 0; i < 16; ++i) {
      buf[offset + i] = rnds[i];
    }

    return buf;
  }

  return (0, _stringify.unsafeStringify)(rnds);
}

var _default = v4;
exports["default"] = _default;

/***/ }),

/***/ 8310:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _v = _interopRequireDefault(__nccwpck_require__(2568));

var _sha = _interopRequireDefault(__nccwpck_require__(6679));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const v5 = (0, _v.default)('v5', 0x50, _sha.default);
var _default = v5;
exports["default"] = _default;

/***/ }),

/***/ 6992:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _regex = _interopRequireDefault(__nccwpck_require__(3194));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function validate(uuid) {
  return typeof uuid === 'string' && _regex.default.test(uuid);
}

var _default = validate;
exports["default"] = _default;

/***/ }),

/***/ 7780:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _validate = _interopRequireDefault(__nccwpck_require__(6992));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function version(uuid) {
  if (!(0, _validate.default)(uuid)) {
    throw TypeError('Invalid UUID');
  }

  return parseInt(uuid.slice(14, 15), 16);
}

var _default = version;
exports["default"] = _default;

/***/ }),

/***/ 1238:
/***/ ((module) => {

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  deserializerMiddleware: () => deserializerMiddleware,
  deserializerMiddlewareOption: () => deserializerMiddlewareOption,
  getSerdePlugin: () => getSerdePlugin,
  serializerMiddleware: () => serializerMiddleware,
  serializerMiddlewareOption: () => serializerMiddlewareOption
});
module.exports = __toCommonJS(src_exports);

// src/deserializerMiddleware.ts
var deserializerMiddleware = /* @__PURE__ */ __name((options, deserializer) => (next) => async (args) => {
  const { response } = await next(args);
  try {
    const parsed = await deserializer(response, options);
    return {
      response,
      output: parsed
    };
  } catch (error) {
    Object.defineProperty(error, "$response", {
      value: response
    });
    if (!("$metadata" in error)) {
      const hint = `Deserialization error: to see the raw response, inspect the hidden field {error}.$response on this object.`;
      error.message += "\n  " + hint;
      if (typeof error.$responseBodyText !== "undefined") {
        if (error.$response) {
          error.$response.body = error.$responseBodyText;
        }
      }
    }
    throw error;
  }
}, "deserializerMiddleware");

// src/serializerMiddleware.ts
var serializerMiddleware = /* @__PURE__ */ __name((options, serializer) => (next, context) => async (args) => {
  var _a;
  const endpoint = ((_a = context.endpointV2) == null ? void 0 : _a.url) && options.urlParser ? async () => options.urlParser(context.endpointV2.url) : options.endpoint;
  if (!endpoint) {
    throw new Error("No valid endpoint provider available.");
  }
  const request = await serializer(args.input, { ...options, endpoint });
  return next({
    ...args,
    request
  });
}, "serializerMiddleware");

// src/serdePlugin.ts
var deserializerMiddlewareOption = {
  name: "deserializerMiddleware",
  step: "deserialize",
  tags: ["DESERIALIZER"],
  override: true
};
var serializerMiddlewareOption = {
  name: "serializerMiddleware",
  step: "serialize",
  tags: ["SERIALIZER"],
  override: true
};
function getSerdePlugin(config, serializer, deserializer) {
  return {
    applyToStack: (commandStack) => {
      commandStack.add(deserializerMiddleware(config, deserializer), deserializerMiddlewareOption);
      commandStack.add(serializerMiddleware(config, serializer), serializerMiddlewareOption);
    }
  };
}
__name(getSerdePlugin, "getSerdePlugin");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 7911:
/***/ ((module) => {

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  constructStack: () => constructStack
});
module.exports = __toCommonJS(src_exports);

// src/MiddlewareStack.ts
var getAllAliases = /* @__PURE__ */ __name((name, aliases) => {
  const _aliases = [];
  if (name) {
    _aliases.push(name);
  }
  if (aliases) {
    for (const alias of aliases) {
      _aliases.push(alias);
    }
  }
  return _aliases;
}, "getAllAliases");
var getMiddlewareNameWithAliases = /* @__PURE__ */ __name((name, aliases) => {
  return `${name || "anonymous"}${aliases && aliases.length > 0 ? ` (a.k.a. ${aliases.join(",")})` : ""}`;
}, "getMiddlewareNameWithAliases");
var constructStack = /* @__PURE__ */ __name(() => {
  let absoluteEntries = [];
  let relativeEntries = [];
  let identifyOnResolve = false;
  const entriesNameSet = /* @__PURE__ */ new Set();
  const sort = /* @__PURE__ */ __name((entries) => entries.sort(
    (a, b) => stepWeights[b.step] - stepWeights[a.step] || priorityWeights[b.priority || "normal"] - priorityWeights[a.priority || "normal"]
  ), "sort");
  const removeByName = /* @__PURE__ */ __name((toRemove) => {
    let isRemoved = false;
    const filterCb = /* @__PURE__ */ __name((entry) => {
      const aliases = getAllAliases(entry.name, entry.aliases);
      if (aliases.includes(toRemove)) {
        isRemoved = true;
        for (const alias of aliases) {
          entriesNameSet.delete(alias);
        }
        return false;
      }
      return true;
    }, "filterCb");
    absoluteEntries = absoluteEntries.filter(filterCb);
    relativeEntries = relativeEntries.filter(filterCb);
    return isRemoved;
  }, "removeByName");
  const removeByReference = /* @__PURE__ */ __name((toRemove) => {
    let isRemoved = false;
    const filterCb = /* @__PURE__ */ __name((entry) => {
      if (entry.middleware === toRemove) {
        isRemoved = true;
        for (const alias of getAllAliases(entry.name, entry.aliases)) {
          entriesNameSet.delete(alias);
        }
        return false;
      }
      return true;
    }, "filterCb");
    absoluteEntries = absoluteEntries.filter(filterCb);
    relativeEntries = relativeEntries.filter(filterCb);
    return isRemoved;
  }, "removeByReference");
  const cloneTo = /* @__PURE__ */ __name((toStack) => {
    var _a;
    absoluteEntries.forEach((entry) => {
      toStack.add(entry.middleware, { ...entry });
    });
    relativeEntries.forEach((entry) => {
      toStack.addRelativeTo(entry.middleware, { ...entry });
    });
    (_a = toStack.identifyOnResolve) == null ? void 0 : _a.call(toStack, stack.identifyOnResolve());
    return toStack;
  }, "cloneTo");
  const expandRelativeMiddlewareList = /* @__PURE__ */ __name((from) => {
    const expandedMiddlewareList = [];
    from.before.forEach((entry) => {
      if (entry.before.length === 0 && entry.after.length === 0) {
        expandedMiddlewareList.push(entry);
      } else {
        expandedMiddlewareList.push(...expandRelativeMiddlewareList(entry));
      }
    });
    expandedMiddlewareList.push(from);
    from.after.reverse().forEach((entry) => {
      if (entry.before.length === 0 && entry.after.length === 0) {
        expandedMiddlewareList.push(entry);
      } else {
        expandedMiddlewareList.push(...expandRelativeMiddlewareList(entry));
      }
    });
    return expandedMiddlewareList;
  }, "expandRelativeMiddlewareList");
  const getMiddlewareList = /* @__PURE__ */ __name((debug = false) => {
    const normalizedAbsoluteEntries = [];
    const normalizedRelativeEntries = [];
    const normalizedEntriesNameMap = {};
    absoluteEntries.forEach((entry) => {
      const normalizedEntry = {
        ...entry,
        before: [],
        after: []
      };
      for (const alias of getAllAliases(normalizedEntry.name, normalizedEntry.aliases)) {
        normalizedEntriesNameMap[alias] = normalizedEntry;
      }
      normalizedAbsoluteEntries.push(normalizedEntry);
    });
    relativeEntries.forEach((entry) => {
      const normalizedEntry = {
        ...entry,
        before: [],
        after: []
      };
      for (const alias of getAllAliases(normalizedEntry.name, normalizedEntry.aliases)) {
        normalizedEntriesNameMap[alias] = normalizedEntry;
      }
      normalizedRelativeEntries.push(normalizedEntry);
    });
    normalizedRelativeEntries.forEach((entry) => {
      if (entry.toMiddleware) {
        const toMiddleware = normalizedEntriesNameMap[entry.toMiddleware];
        if (toMiddleware === void 0) {
          if (debug) {
            return;
          }
          throw new Error(
            `${entry.toMiddleware} is not found when adding ${getMiddlewareNameWithAliases(entry.name, entry.aliases)} middleware ${entry.relation} ${entry.toMiddleware}`
          );
        }
        if (entry.relation === "after") {
          toMiddleware.after.push(entry);
        }
        if (entry.relation === "before") {
          toMiddleware.before.push(entry);
        }
      }
    });
    const mainChain = sort(normalizedAbsoluteEntries).map(expandRelativeMiddlewareList).reduce(
      (wholeList, expandedMiddlewareList) => {
        wholeList.push(...expandedMiddlewareList);
        return wholeList;
      },
      []
    );
    return mainChain;
  }, "getMiddlewareList");
  const stack = {
    add: (middleware, options = {}) => {
      const { name, override, aliases: _aliases } = options;
      const entry = {
        step: "initialize",
        priority: "normal",
        middleware,
        ...options
      };
      const aliases = getAllAliases(name, _aliases);
      if (aliases.length > 0) {
        if (aliases.some((alias) => entriesNameSet.has(alias))) {
          if (!override)
            throw new Error(`Duplicate middleware name '${getMiddlewareNameWithAliases(name, _aliases)}'`);
          for (const alias of aliases) {
            const toOverrideIndex = absoluteEntries.findIndex(
              (entry2) => {
                var _a;
                return entry2.name === alias || ((_a = entry2.aliases) == null ? void 0 : _a.some((a) => a === alias));
              }
            );
            if (toOverrideIndex === -1) {
              continue;
            }
            const toOverride = absoluteEntries[toOverrideIndex];
            if (toOverride.step !== entry.step || entry.priority !== toOverride.priority) {
              throw new Error(
                `"${getMiddlewareNameWithAliases(toOverride.name, toOverride.aliases)}" middleware with ${toOverride.priority} priority in ${toOverride.step} step cannot be overridden by "${getMiddlewareNameWithAliases(name, _aliases)}" middleware with ${entry.priority} priority in ${entry.step} step.`
              );
            }
            absoluteEntries.splice(toOverrideIndex, 1);
          }
        }
        for (const alias of aliases) {
          entriesNameSet.add(alias);
        }
      }
      absoluteEntries.push(entry);
    },
    addRelativeTo: (middleware, options) => {
      const { name, override, aliases: _aliases } = options;
      const entry = {
        middleware,
        ...options
      };
      const aliases = getAllAliases(name, _aliases);
      if (aliases.length > 0) {
        if (aliases.some((alias) => entriesNameSet.has(alias))) {
          if (!override)
            throw new Error(`Duplicate middleware name '${getMiddlewareNameWithAliases(name, _aliases)}'`);
          for (const alias of aliases) {
            const toOverrideIndex = relativeEntries.findIndex(
              (entry2) => {
                var _a;
                return entry2.name === alias || ((_a = entry2.aliases) == null ? void 0 : _a.some((a) => a === alias));
              }
            );
            if (toOverrideIndex === -1) {
              continue;
            }
            const toOverride = relativeEntries[toOverrideIndex];
            if (toOverride.toMiddleware !== entry.toMiddleware || toOverride.relation !== entry.relation) {
              throw new Error(
                `"${getMiddlewareNameWithAliases(toOverride.name, toOverride.aliases)}" middleware ${toOverride.relation} "${toOverride.toMiddleware}" middleware cannot be overridden by "${getMiddlewareNameWithAliases(name, _aliases)}" middleware ${entry.relation} "${entry.toMiddleware}" middleware.`
              );
            }
            relativeEntries.splice(toOverrideIndex, 1);
          }
        }
        for (const alias of aliases) {
          entriesNameSet.add(alias);
        }
      }
      relativeEntries.push(entry);
    },
    clone: () => cloneTo(constructStack()),
    use: (plugin) => {
      plugin.applyToStack(stack);
    },
    remove: (toRemove) => {
      if (typeof toRemove === "string")
        return removeByName(toRemove);
      else
        return removeByReference(toRemove);
    },
    removeByTag: (toRemove) => {
      let isRemoved = false;
      const filterCb = /* @__PURE__ */ __name((entry) => {
        const { tags, name, aliases: _aliases } = entry;
        if (tags && tags.includes(toRemove)) {
          const aliases = getAllAliases(name, _aliases);
          for (const alias of aliases) {
            entriesNameSet.delete(alias);
          }
          isRemoved = true;
          return false;
        }
        return true;
      }, "filterCb");
      absoluteEntries = absoluteEntries.filter(filterCb);
      relativeEntries = relativeEntries.filter(filterCb);
      return isRemoved;
    },
    concat: (from) => {
      var _a;
      const cloned = cloneTo(constructStack());
      cloned.use(from);
      cloned.identifyOnResolve(
        identifyOnResolve || cloned.identifyOnResolve() || (((_a = from.identifyOnResolve) == null ? void 0 : _a.call(from)) ?? false)
      );
      return cloned;
    },
    applyToStack: cloneTo,
    identify: () => {
      return getMiddlewareList(true).map((mw) => {
        const step = mw.step ?? mw.relation + " " + mw.toMiddleware;
        return getMiddlewareNameWithAliases(mw.name, mw.aliases) + " - " + step;
      });
    },
    identifyOnResolve(toggle) {
      if (typeof toggle === "boolean")
        identifyOnResolve = toggle;
      return identifyOnResolve;
    },
    resolve: (handler, context) => {
      for (const middleware of getMiddlewareList().map((entry) => entry.middleware).reverse()) {
        handler = middleware(handler, context);
      }
      if (identifyOnResolve) {
        console.log(stack.identify());
      }
      return handler;
    }
  };
  return stack;
}, "constructStack");
var stepWeights = {
  initialize: 5,
  serialize: 4,
  build: 3,
  finalizeRequest: 2,
  deserialize: 1
};
var priorityWeights = {
  high: 3,
  normal: 2,
  low: 1
};
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 3461:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  loadConfig: () => loadConfig
});
module.exports = __toCommonJS(src_exports);

// src/configLoader.ts


// src/fromEnv.ts
var import_property_provider = __nccwpck_require__(9721);

// src/getSelectorName.ts
function getSelectorName(functionString) {
  try {
    const constants = new Set(Array.from(functionString.match(/([A-Z_]){3,}/g) ?? []));
    constants.delete("CONFIG");
    constants.delete("CONFIG_PREFIX_SEPARATOR");
    constants.delete("ENV");
    return [...constants].join(", ");
  } catch (e) {
    return functionString;
  }
}
__name(getSelectorName, "getSelectorName");

// src/fromEnv.ts
var fromEnv = /* @__PURE__ */ __name((envVarSelector, logger) => async () => {
  try {
    const config = envVarSelector(process.env);
    if (config === void 0) {
      throw new Error();
    }
    return config;
  } catch (e) {
    throw new import_property_provider.CredentialsProviderError(
      e.message || `Not found in ENV: ${getSelectorName(envVarSelector.toString())}`,
      { logger }
    );
  }
}, "fromEnv");

// src/fromSharedConfigFiles.ts

var import_shared_ini_file_loader = __nccwpck_require__(3507);
var fromSharedConfigFiles = /* @__PURE__ */ __name((configSelector, { preferredFile = "config", ...init } = {}) => async () => {
  const profile = (0, import_shared_ini_file_loader.getProfileName)(init);
  const { configFile, credentialsFile } = await (0, import_shared_ini_file_loader.loadSharedConfigFiles)(init);
  const profileFromCredentials = credentialsFile[profile] || {};
  const profileFromConfig = configFile[profile] || {};
  const mergedProfile = preferredFile === "config" ? { ...profileFromCredentials, ...profileFromConfig } : { ...profileFromConfig, ...profileFromCredentials };
  try {
    const cfgFile = preferredFile === "config" ? configFile : credentialsFile;
    const configValue = configSelector(mergedProfile, cfgFile);
    if (configValue === void 0) {
      throw new Error();
    }
    return configValue;
  } catch (e) {
    throw new import_property_provider.CredentialsProviderError(
      e.message || `Not found in config files w/ profile [${profile}]: ${getSelectorName(configSelector.toString())}`,
      { logger: init.logger }
    );
  }
}, "fromSharedConfigFiles");

// src/fromStatic.ts

var isFunction = /* @__PURE__ */ __name((func) => typeof func === "function", "isFunction");
var fromStatic = /* @__PURE__ */ __name((defaultValue) => isFunction(defaultValue) ? async () => await defaultValue() : (0, import_property_provider.fromStatic)(defaultValue), "fromStatic");

// src/configLoader.ts
var loadConfig = /* @__PURE__ */ __name(({ environmentVariableSelector, configFileSelector, default: defaultValue }, configuration = {}) => (0, import_property_provider.memoize)(
  (0, import_property_provider.chain)(
    fromEnv(environmentVariableSelector),
    fromSharedConfigFiles(configFileSelector, configuration),
    fromStatic(defaultValue)
  )
), "loadConfig");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 258:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  DEFAULT_REQUEST_TIMEOUT: () => DEFAULT_REQUEST_TIMEOUT,
  NodeHttp2Handler: () => NodeHttp2Handler,
  NodeHttpHandler: () => NodeHttpHandler,
  streamCollector: () => streamCollector
});
module.exports = __toCommonJS(src_exports);

// src/node-http-handler.ts
var import_protocol_http = __nccwpck_require__(4418);
var import_querystring_builder = __nccwpck_require__(8031);
var import_http = __nccwpck_require__(3685);
var import_https = __nccwpck_require__(5687);

// src/constants.ts
var NODEJS_TIMEOUT_ERROR_CODES = ["ECONNRESET", "EPIPE", "ETIMEDOUT"];

// src/get-transformed-headers.ts
var getTransformedHeaders = /* @__PURE__ */ __name((headers) => {
  const transformedHeaders = {};
  for (const name of Object.keys(headers)) {
    const headerValues = headers[name];
    transformedHeaders[name] = Array.isArray(headerValues) ? headerValues.join(",") : headerValues;
  }
  return transformedHeaders;
}, "getTransformedHeaders");

// src/set-connection-timeout.ts
var setConnectionTimeout = /* @__PURE__ */ __name((request, reject, timeoutInMs = 0) => {
  if (!timeoutInMs) {
    return;
  }
  const timeoutId = setTimeout(() => {
    request.destroy();
    reject(
      Object.assign(new Error(`Socket timed out without establishing a connection within ${timeoutInMs} ms`), {
        name: "TimeoutError"
      })
    );
  }, timeoutInMs);
  request.on("socket", (socket) => {
    if (socket.connecting) {
      socket.on("connect", () => {
        clearTimeout(timeoutId);
      });
    } else {
      clearTimeout(timeoutId);
    }
  });
}, "setConnectionTimeout");

// src/set-socket-keep-alive.ts
var setSocketKeepAlive = /* @__PURE__ */ __name((request, { keepAlive, keepAliveMsecs }) => {
  if (keepAlive !== true) {
    return;
  }
  request.on("socket", (socket) => {
    socket.setKeepAlive(keepAlive, keepAliveMsecs || 0);
  });
}, "setSocketKeepAlive");

// src/set-socket-timeout.ts
var setSocketTimeout = /* @__PURE__ */ __name((request, reject, timeoutInMs = 0) => {
  request.setTimeout(timeoutInMs, () => {
    request.destroy();
    reject(Object.assign(new Error(`Connection timed out after ${timeoutInMs} ms`), { name: "TimeoutError" }));
  });
}, "setSocketTimeout");

// src/write-request-body.ts
var import_stream = __nccwpck_require__(2781);
var MIN_WAIT_TIME = 1e3;
async function writeRequestBody(httpRequest, request, maxContinueTimeoutMs = MIN_WAIT_TIME) {
  const headers = request.headers ?? {};
  const expect = headers["Expect"] || headers["expect"];
  let timeoutId = -1;
  let hasError = false;
  if (expect === "100-continue") {
    await Promise.race([
      new Promise((resolve) => {
        timeoutId = Number(setTimeout(resolve, Math.max(MIN_WAIT_TIME, maxContinueTimeoutMs)));
      }),
      new Promise((resolve) => {
        httpRequest.on("continue", () => {
          clearTimeout(timeoutId);
          resolve();
        });
        httpRequest.on("error", () => {
          hasError = true;
          clearTimeout(timeoutId);
          resolve();
        });
      })
    ]);
  }
  if (!hasError) {
    writeBody(httpRequest, request.body);
  }
}
__name(writeRequestBody, "writeRequestBody");
function writeBody(httpRequest, body) {
  if (body instanceof import_stream.Readable) {
    body.pipe(httpRequest);
    return;
  }
  if (body) {
    if (Buffer.isBuffer(body) || typeof body === "string") {
      httpRequest.end(body);
      return;
    }
    const uint8 = body;
    if (typeof uint8 === "object" && uint8.buffer && typeof uint8.byteOffset === "number" && typeof uint8.byteLength === "number") {
      httpRequest.end(Buffer.from(uint8.buffer, uint8.byteOffset, uint8.byteLength));
      return;
    }
    httpRequest.end(Buffer.from(body));
    return;
  }
  httpRequest.end();
}
__name(writeBody, "writeBody");

// src/node-http-handler.ts
var DEFAULT_REQUEST_TIMEOUT = 0;
var _NodeHttpHandler = class _NodeHttpHandler {
  constructor(options) {
    this.socketWarningTimestamp = 0;
    // Node http handler is hard-coded to http/1.1: https://github.com/nodejs/node/blob/ff5664b83b89c55e4ab5d5f60068fb457f1f5872/lib/_http_server.js#L286
    this.metadata = { handlerProtocol: "http/1.1" };
    this.configProvider = new Promise((resolve, reject) => {
      if (typeof options === "function") {
        options().then((_options) => {
          resolve(this.resolveDefaultConfig(_options));
        }).catch(reject);
      } else {
        resolve(this.resolveDefaultConfig(options));
      }
    });
  }
  /**
   * @returns the input if it is an HttpHandler of any class,
   * or instantiates a new instance of this handler.
   */
  static create(instanceOrOptions) {
    if (typeof (instanceOrOptions == null ? void 0 : instanceOrOptions.handle) === "function") {
      return instanceOrOptions;
    }
    return new _NodeHttpHandler(instanceOrOptions);
  }
  /**
   * @internal
   *
   * @param agent - http(s) agent in use by the NodeHttpHandler instance.
   * @param socketWarningTimestamp - last socket usage check timestamp.
   * @param logger - channel for the warning.
   * @returns timestamp of last emitted warning.
   */
  static checkSocketUsage(agent, socketWarningTimestamp, logger = console) {
    var _a, _b, _c;
    const { sockets, requests, maxSockets } = agent;
    if (typeof maxSockets !== "number" || maxSockets === Infinity) {
      return socketWarningTimestamp;
    }
    const interval = 15e3;
    if (Date.now() - interval < socketWarningTimestamp) {
      return socketWarningTimestamp;
    }
    if (sockets && requests) {
      for (const origin in sockets) {
        const socketsInUse = ((_a = sockets[origin]) == null ? void 0 : _a.length) ?? 0;
        const requestsEnqueued = ((_b = requests[origin]) == null ? void 0 : _b.length) ?? 0;
        if (socketsInUse >= maxSockets && requestsEnqueued >= 2 * maxSockets) {
          (_c = logger == null ? void 0 : logger.warn) == null ? void 0 : _c.call(
            logger,
            `@smithy/node-http-handler:WARN - socket usage at capacity=${socketsInUse} and ${requestsEnqueued} additional requests are enqueued.
See https://docs.aws.amazon.com/sdk-for-javascript/v3/developer-guide/node-configuring-maxsockets.html
or increase socketAcquisitionWarningTimeout=(millis) in the NodeHttpHandler config.`
          );
          return Date.now();
        }
      }
    }
    return socketWarningTimestamp;
  }
  resolveDefaultConfig(options) {
    const { requestTimeout, connectionTimeout, socketTimeout, httpAgent, httpsAgent } = options || {};
    const keepAlive = true;
    const maxSockets = 50;
    return {
      connectionTimeout,
      requestTimeout: requestTimeout ?? socketTimeout,
      httpAgent: (() => {
        if (httpAgent instanceof import_http.Agent || typeof (httpAgent == null ? void 0 : httpAgent.destroy) === "function") {
          return httpAgent;
        }
        return new import_http.Agent({ keepAlive, maxSockets, ...httpAgent });
      })(),
      httpsAgent: (() => {
        if (httpsAgent instanceof import_https.Agent || typeof (httpsAgent == null ? void 0 : httpsAgent.destroy) === "function") {
          return httpsAgent;
        }
        return new import_https.Agent({ keepAlive, maxSockets, ...httpsAgent });
      })(),
      logger: console
    };
  }
  destroy() {
    var _a, _b, _c, _d;
    (_b = (_a = this.config) == null ? void 0 : _a.httpAgent) == null ? void 0 : _b.destroy();
    (_d = (_c = this.config) == null ? void 0 : _c.httpsAgent) == null ? void 0 : _d.destroy();
  }
  async handle(request, { abortSignal } = {}) {
    if (!this.config) {
      this.config = await this.configProvider;
    }
    let socketCheckTimeoutId;
    return new Promise((_resolve, _reject) => {
      let writeRequestBodyPromise = void 0;
      const resolve = /* @__PURE__ */ __name(async (arg) => {
        await writeRequestBodyPromise;
        clearTimeout(socketCheckTimeoutId);
        _resolve(arg);
      }, "resolve");
      const reject = /* @__PURE__ */ __name(async (arg) => {
        await writeRequestBodyPromise;
        clearTimeout(socketCheckTimeoutId);
        _reject(arg);
      }, "reject");
      if (!this.config) {
        throw new Error("Node HTTP request handler config is not resolved");
      }
      if (abortSignal == null ? void 0 : abortSignal.aborted) {
        const abortError = new Error("Request aborted");
        abortError.name = "AbortError";
        reject(abortError);
        return;
      }
      const isSSL = request.protocol === "https:";
      const agent = isSSL ? this.config.httpsAgent : this.config.httpAgent;
      socketCheckTimeoutId = setTimeout(
        () => {
          this.socketWarningTimestamp = _NodeHttpHandler.checkSocketUsage(
            agent,
            this.socketWarningTimestamp,
            this.config.logger
          );
        },
        this.config.socketAcquisitionWarningTimeout ?? (this.config.requestTimeout ?? 2e3) + (this.config.connectionTimeout ?? 1e3)
      );
      const queryString = (0, import_querystring_builder.buildQueryString)(request.query || {});
      let auth = void 0;
      if (request.username != null || request.password != null) {
        const username = request.username ?? "";
        const password = request.password ?? "";
        auth = `${username}:${password}`;
      }
      let path = request.path;
      if (queryString) {
        path += `?${queryString}`;
      }
      if (request.fragment) {
        path += `#${request.fragment}`;
      }
      const nodeHttpsOptions = {
        headers: request.headers,
        host: request.hostname,
        method: request.method,
        path,
        port: request.port,
        agent,
        auth
      };
      const requestFunc = isSSL ? import_https.request : import_http.request;
      const req = requestFunc(nodeHttpsOptions, (res) => {
        const httpResponse = new import_protocol_http.HttpResponse({
          statusCode: res.statusCode || -1,
          reason: res.statusMessage,
          headers: getTransformedHeaders(res.headers),
          body: res
        });
        resolve({ response: httpResponse });
      });
      req.on("error", (err) => {
        if (NODEJS_TIMEOUT_ERROR_CODES.includes(err.code)) {
          reject(Object.assign(err, { name: "TimeoutError" }));
        } else {
          reject(err);
        }
      });
      setConnectionTimeout(req, reject, this.config.connectionTimeout);
      setSocketTimeout(req, reject, this.config.requestTimeout);
      if (abortSignal) {
        const onAbort = /* @__PURE__ */ __name(() => {
          req.destroy();
          const abortError = new Error("Request aborted");
          abortError.name = "AbortError";
          reject(abortError);
        }, "onAbort");
        if (typeof abortSignal.addEventListener === "function") {
          const signal = abortSignal;
          signal.addEventListener("abort", onAbort, { once: true });
          req.once("close", () => signal.removeEventListener("abort", onAbort));
        } else {
          abortSignal.onabort = onAbort;
        }
      }
      const httpAgent = nodeHttpsOptions.agent;
      if (typeof httpAgent === "object" && "keepAlive" in httpAgent) {
        setSocketKeepAlive(req, {
          // @ts-expect-error keepAlive is not public on httpAgent.
          keepAlive: httpAgent.keepAlive,
          // @ts-expect-error keepAliveMsecs is not public on httpAgent.
          keepAliveMsecs: httpAgent.keepAliveMsecs
        });
      }
      writeRequestBodyPromise = writeRequestBody(req, request, this.config.requestTimeout).catch((e) => {
        clearTimeout(socketCheckTimeoutId);
        return _reject(e);
      });
    });
  }
  updateHttpClientConfig(key, value) {
    this.config = void 0;
    this.configProvider = this.configProvider.then((config) => {
      return {
        ...config,
        [key]: value
      };
    });
  }
  httpHandlerConfigs() {
    return this.config ?? {};
  }
};
__name(_NodeHttpHandler, "NodeHttpHandler");
var NodeHttpHandler = _NodeHttpHandler;

// src/node-http2-handler.ts


var import_http22 = __nccwpck_require__(5158);

// src/node-http2-connection-manager.ts
var import_http2 = __toESM(__nccwpck_require__(5158));

// src/node-http2-connection-pool.ts
var _NodeHttp2ConnectionPool = class _NodeHttp2ConnectionPool {
  constructor(sessions) {
    this.sessions = [];
    this.sessions = sessions ?? [];
  }
  poll() {
    if (this.sessions.length > 0) {
      return this.sessions.shift();
    }
  }
  offerLast(session) {
    this.sessions.push(session);
  }
  contains(session) {
    return this.sessions.includes(session);
  }
  remove(session) {
    this.sessions = this.sessions.filter((s) => s !== session);
  }
  [Symbol.iterator]() {
    return this.sessions[Symbol.iterator]();
  }
  destroy(connection) {
    for (const session of this.sessions) {
      if (session === connection) {
        if (!session.destroyed) {
          session.destroy();
        }
      }
    }
  }
};
__name(_NodeHttp2ConnectionPool, "NodeHttp2ConnectionPool");
var NodeHttp2ConnectionPool = _NodeHttp2ConnectionPool;

// src/node-http2-connection-manager.ts
var _NodeHttp2ConnectionManager = class _NodeHttp2ConnectionManager {
  constructor(config) {
    this.sessionCache = /* @__PURE__ */ new Map();
    this.config = config;
    if (this.config.maxConcurrency && this.config.maxConcurrency <= 0) {
      throw new RangeError("maxConcurrency must be greater than zero.");
    }
  }
  lease(requestContext, connectionConfiguration) {
    const url = this.getUrlString(requestContext);
    const existingPool = this.sessionCache.get(url);
    if (existingPool) {
      const existingSession = existingPool.poll();
      if (existingSession && !this.config.disableConcurrency) {
        return existingSession;
      }
    }
    const session = import_http2.default.connect(url);
    if (this.config.maxConcurrency) {
      session.settings({ maxConcurrentStreams: this.config.maxConcurrency }, (err) => {
        if (err) {
          throw new Error(
            "Fail to set maxConcurrentStreams to " + this.config.maxConcurrency + "when creating new session for " + requestContext.destination.toString()
          );
        }
      });
    }
    session.unref();
    const destroySessionCb = /* @__PURE__ */ __name(() => {
      session.destroy();
      this.deleteSession(url, session);
    }, "destroySessionCb");
    session.on("goaway", destroySessionCb);
    session.on("error", destroySessionCb);
    session.on("frameError", destroySessionCb);
    session.on("close", () => this.deleteSession(url, session));
    if (connectionConfiguration.requestTimeout) {
      session.setTimeout(connectionConfiguration.requestTimeout, destroySessionCb);
    }
    const connectionPool = this.sessionCache.get(url) || new NodeHttp2ConnectionPool();
    connectionPool.offerLast(session);
    this.sessionCache.set(url, connectionPool);
    return session;
  }
  /**
   * Delete a session from the connection pool.
   * @param authority The authority of the session to delete.
   * @param session The session to delete.
   */
  deleteSession(authority, session) {
    const existingConnectionPool = this.sessionCache.get(authority);
    if (!existingConnectionPool) {
      return;
    }
    if (!existingConnectionPool.contains(session)) {
      return;
    }
    existingConnectionPool.remove(session);
    this.sessionCache.set(authority, existingConnectionPool);
  }
  release(requestContext, session) {
    var _a;
    const cacheKey = this.getUrlString(requestContext);
    (_a = this.sessionCache.get(cacheKey)) == null ? void 0 : _a.offerLast(session);
  }
  destroy() {
    for (const [key, connectionPool] of this.sessionCache) {
      for (const session of connectionPool) {
        if (!session.destroyed) {
          session.destroy();
        }
        connectionPool.remove(session);
      }
      this.sessionCache.delete(key);
    }
  }
  setMaxConcurrentStreams(maxConcurrentStreams) {
    if (this.config.maxConcurrency && this.config.maxConcurrency <= 0) {
      throw new RangeError("maxConcurrentStreams must be greater than zero.");
    }
    this.config.maxConcurrency = maxConcurrentStreams;
  }
  setDisableConcurrentStreams(disableConcurrentStreams) {
    this.config.disableConcurrency = disableConcurrentStreams;
  }
  getUrlString(request) {
    return request.destination.toString();
  }
};
__name(_NodeHttp2ConnectionManager, "NodeHttp2ConnectionManager");
var NodeHttp2ConnectionManager = _NodeHttp2ConnectionManager;

// src/node-http2-handler.ts
var _NodeHttp2Handler = class _NodeHttp2Handler {
  constructor(options) {
    this.metadata = { handlerProtocol: "h2" };
    this.connectionManager = new NodeHttp2ConnectionManager({});
    this.configProvider = new Promise((resolve, reject) => {
      if (typeof options === "function") {
        options().then((opts) => {
          resolve(opts || {});
        }).catch(reject);
      } else {
        resolve(options || {});
      }
    });
  }
  /**
   * @returns the input if it is an HttpHandler of any class,
   * or instantiates a new instance of this handler.
   */
  static create(instanceOrOptions) {
    if (typeof (instanceOrOptions == null ? void 0 : instanceOrOptions.handle) === "function") {
      return instanceOrOptions;
    }
    return new _NodeHttp2Handler(instanceOrOptions);
  }
  destroy() {
    this.connectionManager.destroy();
  }
  async handle(request, { abortSignal } = {}) {
    if (!this.config) {
      this.config = await this.configProvider;
      this.connectionManager.setDisableConcurrentStreams(this.config.disableConcurrentStreams || false);
      if (this.config.maxConcurrentStreams) {
        this.connectionManager.setMaxConcurrentStreams(this.config.maxConcurrentStreams);
      }
    }
    const { requestTimeout, disableConcurrentStreams } = this.config;
    return new Promise((_resolve, _reject) => {
      var _a;
      let fulfilled = false;
      let writeRequestBodyPromise = void 0;
      const resolve = /* @__PURE__ */ __name(async (arg) => {
        await writeRequestBodyPromise;
        _resolve(arg);
      }, "resolve");
      const reject = /* @__PURE__ */ __name(async (arg) => {
        await writeRequestBodyPromise;
        _reject(arg);
      }, "reject");
      if (abortSignal == null ? void 0 : abortSignal.aborted) {
        fulfilled = true;
        const abortError = new Error("Request aborted");
        abortError.name = "AbortError";
        reject(abortError);
        return;
      }
      const { hostname, method, port, protocol, query } = request;
      let auth = "";
      if (request.username != null || request.password != null) {
        const username = request.username ?? "";
        const password = request.password ?? "";
        auth = `${username}:${password}@`;
      }
      const authority = `${protocol}//${auth}${hostname}${port ? `:${port}` : ""}`;
      const requestContext = { destination: new URL(authority) };
      const session = this.connectionManager.lease(requestContext, {
        requestTimeout: (_a = this.config) == null ? void 0 : _a.sessionTimeout,
        disableConcurrentStreams: disableConcurrentStreams || false
      });
      const rejectWithDestroy = /* @__PURE__ */ __name((err) => {
        if (disableConcurrentStreams) {
          this.destroySession(session);
        }
        fulfilled = true;
        reject(err);
      }, "rejectWithDestroy");
      const queryString = (0, import_querystring_builder.buildQueryString)(query || {});
      let path = request.path;
      if (queryString) {
        path += `?${queryString}`;
      }
      if (request.fragment) {
        path += `#${request.fragment}`;
      }
      const req = session.request({
        ...request.headers,
        [import_http22.constants.HTTP2_HEADER_PATH]: path,
        [import_http22.constants.HTTP2_HEADER_METHOD]: method
      });
      session.ref();
      req.on("response", (headers) => {
        const httpResponse = new import_protocol_http.HttpResponse({
          statusCode: headers[":status"] || -1,
          headers: getTransformedHeaders(headers),
          body: req
        });
        fulfilled = true;
        resolve({ response: httpResponse });
        if (disableConcurrentStreams) {
          session.close();
          this.connectionManager.deleteSession(authority, session);
        }
      });
      if (requestTimeout) {
        req.setTimeout(requestTimeout, () => {
          req.close();
          const timeoutError = new Error(`Stream timed out because of no activity for ${requestTimeout} ms`);
          timeoutError.name = "TimeoutError";
          rejectWithDestroy(timeoutError);
        });
      }
      if (abortSignal) {
        const onAbort = /* @__PURE__ */ __name(() => {
          req.close();
          const abortError = new Error("Request aborted");
          abortError.name = "AbortError";
          rejectWithDestroy(abortError);
        }, "onAbort");
        if (typeof abortSignal.addEventListener === "function") {
          const signal = abortSignal;
          signal.addEventListener("abort", onAbort, { once: true });
          req.once("close", () => signal.removeEventListener("abort", onAbort));
        } else {
          abortSignal.onabort = onAbort;
        }
      }
      req.on("frameError", (type, code, id) => {
        rejectWithDestroy(new Error(`Frame type id ${type} in stream id ${id} has failed with code ${code}.`));
      });
      req.on("error", rejectWithDestroy);
      req.on("aborted", () => {
        rejectWithDestroy(
          new Error(`HTTP/2 stream is abnormally aborted in mid-communication with result code ${req.rstCode}.`)
        );
      });
      req.on("close", () => {
        session.unref();
        if (disableConcurrentStreams) {
          session.destroy();
        }
        if (!fulfilled) {
          rejectWithDestroy(new Error("Unexpected error: http2 request did not get a response"));
        }
      });
      writeRequestBodyPromise = writeRequestBody(req, request, requestTimeout);
    });
  }
  updateHttpClientConfig(key, value) {
    this.config = void 0;
    this.configProvider = this.configProvider.then((config) => {
      return {
        ...config,
        [key]: value
      };
    });
  }
  httpHandlerConfigs() {
    return this.config ?? {};
  }
  /**
   * Destroys a session.
   * @param session The session to destroy.
   */
  destroySession(session) {
    if (!session.destroyed) {
      session.destroy();
    }
  }
};
__name(_NodeHttp2Handler, "NodeHttp2Handler");
var NodeHttp2Handler = _NodeHttp2Handler;

// src/stream-collector/collector.ts

var _Collector = class _Collector extends import_stream.Writable {
  constructor() {
    super(...arguments);
    this.bufferedBytes = [];
  }
  _write(chunk, encoding, callback) {
    this.bufferedBytes.push(chunk);
    callback();
  }
};
__name(_Collector, "Collector");
var Collector = _Collector;

// src/stream-collector/index.ts
var streamCollector = /* @__PURE__ */ __name((stream) => {
  if (isReadableStreamInstance(stream)) {
    return collectReadableStream(stream);
  }
  return new Promise((resolve, reject) => {
    const collector = new Collector();
    stream.pipe(collector);
    stream.on("error", (err) => {
      collector.end();
      reject(err);
    });
    collector.on("error", reject);
    collector.on("finish", function() {
      const bytes = new Uint8Array(Buffer.concat(this.bufferedBytes));
      resolve(bytes);
    });
  });
}, "streamCollector");
var isReadableStreamInstance = /* @__PURE__ */ __name((stream) => typeof ReadableStream === "function" && stream instanceof ReadableStream, "isReadableStreamInstance");
async function collectReadableStream(stream) {
  const chunks = [];
  const reader = stream.getReader();
  let isDone = false;
  let length = 0;
  while (!isDone) {
    const { done, value } = await reader.read();
    if (value) {
      chunks.push(value);
      length += value.length;
    }
    isDone = done;
  }
  const collected = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    collected.set(chunk, offset);
    offset += chunk.length;
  }
  return collected;
}
__name(collectReadableStream, "collectReadableStream");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 9721:
/***/ ((module) => {

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  CredentialsProviderError: () => CredentialsProviderError,
  ProviderError: () => ProviderError,
  TokenProviderError: () => TokenProviderError,
  chain: () => chain,
  fromStatic: () => fromStatic,
  memoize: () => memoize
});
module.exports = __toCommonJS(src_exports);

// src/ProviderError.ts
var _ProviderError = class _ProviderError extends Error {
  constructor(message, options = true) {
    var _a;
    let logger;
    let tryNextLink = true;
    if (typeof options === "boolean") {
      logger = void 0;
      tryNextLink = options;
    } else if (options != null && typeof options === "object") {
      logger = options.logger;
      tryNextLink = options.tryNextLink ?? true;
    }
    super(message);
    this.name = "ProviderError";
    this.tryNextLink = tryNextLink;
    Object.setPrototypeOf(this, _ProviderError.prototype);
    (_a = logger == null ? void 0 : logger.debug) == null ? void 0 : _a.call(logger, `@smithy/property-provider ${tryNextLink ? "->" : "(!)"} ${message}`);
  }
  /**
   * @deprecated use new operator.
   */
  static from(error, options = true) {
    return Object.assign(new this(error.message, options), error);
  }
};
__name(_ProviderError, "ProviderError");
var ProviderError = _ProviderError;

// src/CredentialsProviderError.ts
var _CredentialsProviderError = class _CredentialsProviderError extends ProviderError {
  /**
   * @override
   */
  constructor(message, options = true) {
    super(message, options);
    this.name = "CredentialsProviderError";
    Object.setPrototypeOf(this, _CredentialsProviderError.prototype);
  }
};
__name(_CredentialsProviderError, "CredentialsProviderError");
var CredentialsProviderError = _CredentialsProviderError;

// src/TokenProviderError.ts
var _TokenProviderError = class _TokenProviderError extends ProviderError {
  /**
   * @override
   */
  constructor(message, options = true) {
    super(message, options);
    this.name = "TokenProviderError";
    Object.setPrototypeOf(this, _TokenProviderError.prototype);
  }
};
__name(_TokenProviderError, "TokenProviderError");
var TokenProviderError = _TokenProviderError;

// src/chain.ts
var chain = /* @__PURE__ */ __name((...providers) => async () => {
  if (providers.length === 0) {
    throw new ProviderError("No providers in chain");
  }
  let lastProviderError;
  for (const provider of providers) {
    try {
      const credentials = await provider();
      return credentials;
    } catch (err) {
      lastProviderError = err;
      if (err == null ? void 0 : err.tryNextLink) {
        continue;
      }
      throw err;
    }
  }
  throw lastProviderError;
}, "chain");

// src/fromStatic.ts
var fromStatic = /* @__PURE__ */ __name((staticValue) => () => Promise.resolve(staticValue), "fromStatic");

// src/memoize.ts
var memoize = /* @__PURE__ */ __name((provider, isExpired, requiresRefresh) => {
  let resolved;
  let pending;
  let hasResult;
  let isConstant = false;
  const coalesceProvider = /* @__PURE__ */ __name(async () => {
    if (!pending) {
      pending = provider();
    }
    try {
      resolved = await pending;
      hasResult = true;
      isConstant = false;
    } finally {
      pending = void 0;
    }
    return resolved;
  }, "coalesceProvider");
  if (isExpired === void 0) {
    return async (options) => {
      if (!hasResult || (options == null ? void 0 : options.forceRefresh)) {
        resolved = await coalesceProvider();
      }
      return resolved;
    };
  }
  return async (options) => {
    if (!hasResult || (options == null ? void 0 : options.forceRefresh)) {
      resolved = await coalesceProvider();
    }
    if (isConstant) {
      return resolved;
    }
    if (requiresRefresh && !requiresRefresh(resolved)) {
      isConstant = true;
      return resolved;
    }
    if (isExpired(resolved)) {
      await coalesceProvider();
      return resolved;
    }
    return resolved;
  };
}, "memoize");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 4418:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  Field: () => Field,
  Fields: () => Fields,
  HttpRequest: () => HttpRequest,
  HttpResponse: () => HttpResponse,
  IHttpRequest: () => import_types.HttpRequest,
  getHttpHandlerExtensionConfiguration: () => getHttpHandlerExtensionConfiguration,
  isValidHostname: () => isValidHostname,
  resolveHttpHandlerRuntimeConfig: () => resolveHttpHandlerRuntimeConfig
});
module.exports = __toCommonJS(src_exports);

// src/extensions/httpExtensionConfiguration.ts
var getHttpHandlerExtensionConfiguration = /* @__PURE__ */ __name((runtimeConfig) => {
  let httpHandler = runtimeConfig.httpHandler;
  return {
    setHttpHandler(handler) {
      httpHandler = handler;
    },
    httpHandler() {
      return httpHandler;
    },
    updateHttpClientConfig(key, value) {
      httpHandler.updateHttpClientConfig(key, value);
    },
    httpHandlerConfigs() {
      return httpHandler.httpHandlerConfigs();
    }
  };
}, "getHttpHandlerExtensionConfiguration");
var resolveHttpHandlerRuntimeConfig = /* @__PURE__ */ __name((httpHandlerExtensionConfiguration) => {
  return {
    httpHandler: httpHandlerExtensionConfiguration.httpHandler()
  };
}, "resolveHttpHandlerRuntimeConfig");

// src/Field.ts
var import_types = __nccwpck_require__(5756);
var _Field = class _Field {
  constructor({ name, kind = import_types.FieldPosition.HEADER, values = [] }) {
    this.name = name;
    this.kind = kind;
    this.values = values;
  }
  /**
   * Appends a value to the field.
   *
   * @param value The value to append.
   */
  add(value) {
    this.values.push(value);
  }
  /**
   * Overwrite existing field values.
   *
   * @param values The new field values.
   */
  set(values) {
    this.values = values;
  }
  /**
   * Remove all matching entries from list.
   *
   * @param value Value to remove.
   */
  remove(value) {
    this.values = this.values.filter((v) => v !== value);
  }
  /**
   * Get comma-delimited string.
   *
   * @returns String representation of {@link Field}.
   */
  toString() {
    return this.values.map((v) => v.includes(",") || v.includes(" ") ? `"${v}"` : v).join(", ");
  }
  /**
   * Get string values as a list
   *
   * @returns Values in {@link Field} as a list.
   */
  get() {
    return this.values;
  }
};
__name(_Field, "Field");
var Field = _Field;

// src/Fields.ts
var _Fields = class _Fields {
  constructor({ fields = [], encoding = "utf-8" }) {
    this.entries = {};
    fields.forEach(this.setField.bind(this));
    this.encoding = encoding;
  }
  /**
   * Set entry for a {@link Field} name. The `name`
   * attribute will be used to key the collection.
   *
   * @param field The {@link Field} to set.
   */
  setField(field) {
    this.entries[field.name.toLowerCase()] = field;
  }
  /**
   *  Retrieve {@link Field} entry by name.
   *
   * @param name The name of the {@link Field} entry
   *  to retrieve
   * @returns The {@link Field} if it exists.
   */
  getField(name) {
    return this.entries[name.toLowerCase()];
  }
  /**
   * Delete entry from collection.
   *
   * @param name Name of the entry to delete.
   */
  removeField(name) {
    delete this.entries[name.toLowerCase()];
  }
  /**
   * Helper function for retrieving specific types of fields.
   * Used to grab all headers or all trailers.
   *
   * @param kind {@link FieldPosition} of entries to retrieve.
   * @returns The {@link Field} entries with the specified
   *  {@link FieldPosition}.
   */
  getByType(kind) {
    return Object.values(this.entries).filter((field) => field.kind === kind);
  }
};
__name(_Fields, "Fields");
var Fields = _Fields;

// src/httpRequest.ts

var _HttpRequest = class _HttpRequest {
  constructor(options) {
    this.method = options.method || "GET";
    this.hostname = options.hostname || "localhost";
    this.port = options.port;
    this.query = options.query || {};
    this.headers = options.headers || {};
    this.body = options.body;
    this.protocol = options.protocol ? options.protocol.slice(-1) !== ":" ? `${options.protocol}:` : options.protocol : "https:";
    this.path = options.path ? options.path.charAt(0) !== "/" ? `/${options.path}` : options.path : "/";
    this.username = options.username;
    this.password = options.password;
    this.fragment = options.fragment;
  }
  /**
   * Note: this does not deep-clone the body.
   */
  static clone(request) {
    const cloned = new _HttpRequest({
      ...request,
      headers: { ...request.headers }
    });
    if (cloned.query) {
      cloned.query = cloneQuery(cloned.query);
    }
    return cloned;
  }
  /**
   * This method only actually asserts that request is the interface {@link IHttpRequest},
   * and not necessarily this concrete class. Left in place for API stability.
   *
   * Do not call instance methods on the input of this function, and
   * do not assume it has the HttpRequest prototype.
   */
  static isInstance(request) {
    if (!request) {
      return false;
    }
    const req = request;
    return "method" in req && "protocol" in req && "hostname" in req && "path" in req && typeof req["query"] === "object" && typeof req["headers"] === "object";
  }
  /**
   * @deprecated use static HttpRequest.clone(request) instead. It's not safe to call
   * this method because {@link HttpRequest.isInstance} incorrectly
   * asserts that IHttpRequest (interface) objects are of type HttpRequest (class).
   */
  clone() {
    return _HttpRequest.clone(this);
  }
};
__name(_HttpRequest, "HttpRequest");
var HttpRequest = _HttpRequest;
function cloneQuery(query) {
  return Object.keys(query).reduce((carry, paramName) => {
    const param = query[paramName];
    return {
      ...carry,
      [paramName]: Array.isArray(param) ? [...param] : param
    };
  }, {});
}
__name(cloneQuery, "cloneQuery");

// src/httpResponse.ts
var _HttpResponse = class _HttpResponse {
  constructor(options) {
    this.statusCode = options.statusCode;
    this.reason = options.reason;
    this.headers = options.headers || {};
    this.body = options.body;
  }
  static isInstance(response) {
    if (!response)
      return false;
    const resp = response;
    return typeof resp.statusCode === "number" && typeof resp.headers === "object";
  }
};
__name(_HttpResponse, "HttpResponse");
var HttpResponse = _HttpResponse;

// src/isValidHostname.ts
function isValidHostname(hostname) {
  const hostPattern = /^[a-z0-9][a-z0-9\.\-]*[a-z0-9]$/;
  return hostPattern.test(hostname);
}
__name(isValidHostname, "isValidHostname");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 8031:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  buildQueryString: () => buildQueryString
});
module.exports = __toCommonJS(src_exports);
var import_util_uri_escape = __nccwpck_require__(4197);
function buildQueryString(query) {
  const parts = [];
  for (let key of Object.keys(query).sort()) {
    const value = query[key];
    key = (0, import_util_uri_escape.escapeUri)(key);
    if (Array.isArray(value)) {
      for (let i = 0, iLen = value.length; i < iLen; i++) {
        parts.push(`${key}=${(0, import_util_uri_escape.escapeUri)(value[i])}`);
      }
    } else {
      let qsEntry = key;
      if (value || typeof value === "string") {
        qsEntry += `=${(0, import_util_uri_escape.escapeUri)(value)}`;
      }
      parts.push(qsEntry);
    }
  }
  return parts.join("&");
}
__name(buildQueryString, "buildQueryString");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 4769:
/***/ ((module) => {

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  parseQueryString: () => parseQueryString
});
module.exports = __toCommonJS(src_exports);
function parseQueryString(querystring) {
  const query = {};
  querystring = querystring.replace(/^\?/, "");
  if (querystring) {
    for (const pair of querystring.split("&")) {
      let [key, value = null] = pair.split("=");
      key = decodeURIComponent(key);
      if (value) {
        value = decodeURIComponent(value);
      }
      if (!(key in query)) {
        query[key] = value;
      } else if (Array.isArray(query[key])) {
        query[key].push(value);
      } else {
        query[key] = [query[key], value];
      }
    }
  }
  return query;
}
__name(parseQueryString, "parseQueryString");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 6375:
/***/ ((module) => {

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  isClockSkewCorrectedError: () => isClockSkewCorrectedError,
  isClockSkewError: () => isClockSkewError,
  isRetryableByTrait: () => isRetryableByTrait,
  isServerError: () => isServerError,
  isThrottlingError: () => isThrottlingError,
  isTransientError: () => isTransientError
});
module.exports = __toCommonJS(src_exports);

// src/constants.ts
var CLOCK_SKEW_ERROR_CODES = [
  "AuthFailure",
  "InvalidSignatureException",
  "RequestExpired",
  "RequestInTheFuture",
  "RequestTimeTooSkewed",
  "SignatureDoesNotMatch"
];
var THROTTLING_ERROR_CODES = [
  "BandwidthLimitExceeded",
  "EC2ThrottledException",
  "LimitExceededException",
  "PriorRequestNotComplete",
  "ProvisionedThroughputExceededException",
  "RequestLimitExceeded",
  "RequestThrottled",
  "RequestThrottledException",
  "SlowDown",
  "ThrottledException",
  "Throttling",
  "ThrottlingException",
  "TooManyRequestsException",
  "TransactionInProgressException"
  // DynamoDB
];
var TRANSIENT_ERROR_CODES = ["TimeoutError", "RequestTimeout", "RequestTimeoutException"];
var TRANSIENT_ERROR_STATUS_CODES = [500, 502, 503, 504];
var NODEJS_TIMEOUT_ERROR_CODES = ["ECONNRESET", "ECONNREFUSED", "EPIPE", "ETIMEDOUT"];

// src/index.ts
var isRetryableByTrait = /* @__PURE__ */ __name((error) => error.$retryable !== void 0, "isRetryableByTrait");
var isClockSkewError = /* @__PURE__ */ __name((error) => CLOCK_SKEW_ERROR_CODES.includes(error.name), "isClockSkewError");
var isClockSkewCorrectedError = /* @__PURE__ */ __name((error) => {
  var _a;
  return (_a = error.$metadata) == null ? void 0 : _a.clockSkewCorrected;
}, "isClockSkewCorrectedError");
var isThrottlingError = /* @__PURE__ */ __name((error) => {
  var _a, _b;
  return ((_a = error.$metadata) == null ? void 0 : _a.httpStatusCode) === 429 || THROTTLING_ERROR_CODES.includes(error.name) || ((_b = error.$retryable) == null ? void 0 : _b.throttling) == true;
}, "isThrottlingError");
var isTransientError = /* @__PURE__ */ __name((error) => {
  var _a;
  return isClockSkewCorrectedError(error) || TRANSIENT_ERROR_CODES.includes(error.name) || NODEJS_TIMEOUT_ERROR_CODES.includes((error == null ? void 0 : error.code) || "") || TRANSIENT_ERROR_STATUS_CODES.includes(((_a = error.$metadata) == null ? void 0 : _a.httpStatusCode) || 0);
}, "isTransientError");
var isServerError = /* @__PURE__ */ __name((error) => {
  var _a;
  if (((_a = error.$metadata) == null ? void 0 : _a.httpStatusCode) !== void 0) {
    const statusCode = error.$metadata.httpStatusCode;
    if (500 <= statusCode && statusCode <= 599 && !isTransientError(error)) {
      return true;
    }
    return false;
  }
  return false;
}, "isServerError");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 8340:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.getHomeDir = void 0;
const os_1 = __nccwpck_require__(2037);
const path_1 = __nccwpck_require__(1017);
const homeDirCache = {};
const getHomeDirCacheKey = () => {
    if (process && process.geteuid) {
        return `${process.geteuid()}`;
    }
    return "DEFAULT";
};
const getHomeDir = () => {
    const { HOME, USERPROFILE, HOMEPATH, HOMEDRIVE = `C:${path_1.sep}` } = process.env;
    if (HOME)
        return HOME;
    if (USERPROFILE)
        return USERPROFILE;
    if (HOMEPATH)
        return `${HOMEDRIVE}${HOMEPATH}`;
    const homeDirCacheKey = getHomeDirCacheKey();
    if (!homeDirCache[homeDirCacheKey])
        homeDirCache[homeDirCacheKey] = (0, os_1.homedir)();
    return homeDirCache[homeDirCacheKey];
};
exports.getHomeDir = getHomeDir;


/***/ }),

/***/ 4740:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.getSSOTokenFilepath = void 0;
const crypto_1 = __nccwpck_require__(6113);
const path_1 = __nccwpck_require__(1017);
const getHomeDir_1 = __nccwpck_require__(8340);
const getSSOTokenFilepath = (id) => {
    const hasher = (0, crypto_1.createHash)("sha1");
    const cacheName = hasher.update(id).digest("hex");
    return (0, path_1.join)((0, getHomeDir_1.getHomeDir)(), ".aws", "sso", "cache", `${cacheName}.json`);
};
exports.getSSOTokenFilepath = getSSOTokenFilepath;


/***/ }),

/***/ 9678:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.getSSOTokenFromFile = void 0;
const fs_1 = __nccwpck_require__(7147);
const getSSOTokenFilepath_1 = __nccwpck_require__(4740);
const { readFile } = fs_1.promises;
const getSSOTokenFromFile = async (id) => {
    const ssoTokenFilepath = (0, getSSOTokenFilepath_1.getSSOTokenFilepath)(id);
    const ssoTokenText = await readFile(ssoTokenFilepath, "utf8");
    return JSON.parse(ssoTokenText);
};
exports.getSSOTokenFromFile = getSSOTokenFromFile;


/***/ }),

/***/ 3507:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __reExport = (target, mod, secondTarget) => (__copyProps(target, mod, "default"), secondTarget && __copyProps(secondTarget, mod, "default"));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  CONFIG_PREFIX_SEPARATOR: () => CONFIG_PREFIX_SEPARATOR,
  DEFAULT_PROFILE: () => DEFAULT_PROFILE,
  ENV_PROFILE: () => ENV_PROFILE,
  getProfileName: () => getProfileName,
  loadSharedConfigFiles: () => loadSharedConfigFiles,
  loadSsoSessionData: () => loadSsoSessionData,
  parseKnownFiles: () => parseKnownFiles
});
module.exports = __toCommonJS(src_exports);
__reExport(src_exports, __nccwpck_require__(8340), module.exports);

// src/getProfileName.ts
var ENV_PROFILE = "AWS_PROFILE";
var DEFAULT_PROFILE = "default";
var getProfileName = /* @__PURE__ */ __name((init) => init.profile || process.env[ENV_PROFILE] || DEFAULT_PROFILE, "getProfileName");

// src/index.ts
__reExport(src_exports, __nccwpck_require__(4740), module.exports);
__reExport(src_exports, __nccwpck_require__(9678), module.exports);

// src/loadSharedConfigFiles.ts


// src/getConfigData.ts
var import_types = __nccwpck_require__(5756);
var getConfigData = /* @__PURE__ */ __name((data) => Object.entries(data).filter(([key]) => {
  const indexOfSeparator = key.indexOf(CONFIG_PREFIX_SEPARATOR);
  if (indexOfSeparator === -1) {
    return false;
  }
  return Object.values(import_types.IniSectionType).includes(key.substring(0, indexOfSeparator));
}).reduce(
  (acc, [key, value]) => {
    const indexOfSeparator = key.indexOf(CONFIG_PREFIX_SEPARATOR);
    const updatedKey = key.substring(0, indexOfSeparator) === import_types.IniSectionType.PROFILE ? key.substring(indexOfSeparator + 1) : key;
    acc[updatedKey] = value;
    return acc;
  },
  {
    // Populate default profile, if present.
    ...data.default && { default: data.default }
  }
), "getConfigData");

// src/getConfigFilepath.ts
var import_path = __nccwpck_require__(1017);
var import_getHomeDir = __nccwpck_require__(8340);
var ENV_CONFIG_PATH = "AWS_CONFIG_FILE";
var getConfigFilepath = /* @__PURE__ */ __name(() => process.env[ENV_CONFIG_PATH] || (0, import_path.join)((0, import_getHomeDir.getHomeDir)(), ".aws", "config"), "getConfigFilepath");

// src/getCredentialsFilepath.ts

var import_getHomeDir2 = __nccwpck_require__(8340);
var ENV_CREDENTIALS_PATH = "AWS_SHARED_CREDENTIALS_FILE";
var getCredentialsFilepath = /* @__PURE__ */ __name(() => process.env[ENV_CREDENTIALS_PATH] || (0, import_path.join)((0, import_getHomeDir2.getHomeDir)(), ".aws", "credentials"), "getCredentialsFilepath");

// src/loadSharedConfigFiles.ts
var import_getHomeDir3 = __nccwpck_require__(8340);

// src/parseIni.ts

var prefixKeyRegex = /^([\w-]+)\s(["'])?([\w-@\+\.%:/]+)\2$/;
var profileNameBlockList = ["__proto__", "profile __proto__"];
var parseIni = /* @__PURE__ */ __name((iniData) => {
  const map = {};
  let currentSection;
  let currentSubSection;
  for (const iniLine of iniData.split(/\r?\n/)) {
    const trimmedLine = iniLine.split(/(^|\s)[;#]/)[0].trim();
    const isSection = trimmedLine[0] === "[" && trimmedLine[trimmedLine.length - 1] === "]";
    if (isSection) {
      currentSection = void 0;
      currentSubSection = void 0;
      const sectionName = trimmedLine.substring(1, trimmedLine.length - 1);
      const matches = prefixKeyRegex.exec(sectionName);
      if (matches) {
        const [, prefix, , name] = matches;
        if (Object.values(import_types.IniSectionType).includes(prefix)) {
          currentSection = [prefix, name].join(CONFIG_PREFIX_SEPARATOR);
        }
      } else {
        currentSection = sectionName;
      }
      if (profileNameBlockList.includes(sectionName)) {
        throw new Error(`Found invalid profile name "${sectionName}"`);
      }
    } else if (currentSection) {
      const indexOfEqualsSign = trimmedLine.indexOf("=");
      if (![0, -1].includes(indexOfEqualsSign)) {
        const [name, value] = [
          trimmedLine.substring(0, indexOfEqualsSign).trim(),
          trimmedLine.substring(indexOfEqualsSign + 1).trim()
        ];
        if (value === "") {
          currentSubSection = name;
        } else {
          if (currentSubSection && iniLine.trimStart() === iniLine) {
            currentSubSection = void 0;
          }
          map[currentSection] = map[currentSection] || {};
          const key = currentSubSection ? [currentSubSection, name].join(CONFIG_PREFIX_SEPARATOR) : name;
          map[currentSection][key] = value;
        }
      }
    }
  }
  return map;
}, "parseIni");

// src/loadSharedConfigFiles.ts
var import_slurpFile = __nccwpck_require__(9155);
var swallowError = /* @__PURE__ */ __name(() => ({}), "swallowError");
var CONFIG_PREFIX_SEPARATOR = ".";
var loadSharedConfigFiles = /* @__PURE__ */ __name(async (init = {}) => {
  const { filepath = getCredentialsFilepath(), configFilepath = getConfigFilepath() } = init;
  const homeDir = (0, import_getHomeDir3.getHomeDir)();
  const relativeHomeDirPrefix = "~/";
  let resolvedFilepath = filepath;
  if (filepath.startsWith(relativeHomeDirPrefix)) {
    resolvedFilepath = (0, import_path.join)(homeDir, filepath.slice(2));
  }
  let resolvedConfigFilepath = configFilepath;
  if (configFilepath.startsWith(relativeHomeDirPrefix)) {
    resolvedConfigFilepath = (0, import_path.join)(homeDir, configFilepath.slice(2));
  }
  const parsedFiles = await Promise.all([
    (0, import_slurpFile.slurpFile)(resolvedConfigFilepath, {
      ignoreCache: init.ignoreCache
    }).then(parseIni).then(getConfigData).catch(swallowError),
    (0, import_slurpFile.slurpFile)(resolvedFilepath, {
      ignoreCache: init.ignoreCache
    }).then(parseIni).catch(swallowError)
  ]);
  return {
    configFile: parsedFiles[0],
    credentialsFile: parsedFiles[1]
  };
}, "loadSharedConfigFiles");

// src/getSsoSessionData.ts

var getSsoSessionData = /* @__PURE__ */ __name((data) => Object.entries(data).filter(([key]) => key.startsWith(import_types.IniSectionType.SSO_SESSION + CONFIG_PREFIX_SEPARATOR)).reduce((acc, [key, value]) => ({ ...acc, [key.substring(key.indexOf(CONFIG_PREFIX_SEPARATOR) + 1)]: value }), {}), "getSsoSessionData");

// src/loadSsoSessionData.ts
var import_slurpFile2 = __nccwpck_require__(9155);
var swallowError2 = /* @__PURE__ */ __name(() => ({}), "swallowError");
var loadSsoSessionData = /* @__PURE__ */ __name(async (init = {}) => (0, import_slurpFile2.slurpFile)(init.configFilepath ?? getConfigFilepath()).then(parseIni).then(getSsoSessionData).catch(swallowError2), "loadSsoSessionData");

// src/mergeConfigFiles.ts
var mergeConfigFiles = /* @__PURE__ */ __name((...files) => {
  const merged = {};
  for (const file of files) {
    for (const [key, values] of Object.entries(file)) {
      if (merged[key] !== void 0) {
        Object.assign(merged[key], values);
      } else {
        merged[key] = values;
      }
    }
  }
  return merged;
}, "mergeConfigFiles");

// src/parseKnownFiles.ts
var parseKnownFiles = /* @__PURE__ */ __name(async (init) => {
  const parsedFiles = await loadSharedConfigFiles(init);
  return mergeConfigFiles(parsedFiles.configFile, parsedFiles.credentialsFile);
}, "parseKnownFiles");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 9155:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.slurpFile = void 0;
const fs_1 = __nccwpck_require__(7147);
const { readFile } = fs_1.promises;
const filePromisesHash = {};
const slurpFile = (path, options) => {
    if (!filePromisesHash[path] || (options === null || options === void 0 ? void 0 : options.ignoreCache)) {
        filePromisesHash[path] = readFile(path, "utf8");
    }
    return filePromisesHash[path];
};
exports.slurpFile = slurpFile;


/***/ }),

/***/ 1528:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  SignatureV4: () => SignatureV4,
  clearCredentialCache: () => clearCredentialCache,
  createScope: () => createScope,
  getCanonicalHeaders: () => getCanonicalHeaders,
  getCanonicalQuery: () => getCanonicalQuery,
  getPayloadHash: () => getPayloadHash,
  getSigningKey: () => getSigningKey,
  moveHeadersToQuery: () => moveHeadersToQuery,
  prepareRequest: () => prepareRequest
});
module.exports = __toCommonJS(src_exports);

// src/SignatureV4.ts

var import_util_middleware = __nccwpck_require__(2390);

var import_util_utf84 = __nccwpck_require__(1895);

// src/constants.ts
var ALGORITHM_QUERY_PARAM = "X-Amz-Algorithm";
var CREDENTIAL_QUERY_PARAM = "X-Amz-Credential";
var AMZ_DATE_QUERY_PARAM = "X-Amz-Date";
var SIGNED_HEADERS_QUERY_PARAM = "X-Amz-SignedHeaders";
var EXPIRES_QUERY_PARAM = "X-Amz-Expires";
var SIGNATURE_QUERY_PARAM = "X-Amz-Signature";
var TOKEN_QUERY_PARAM = "X-Amz-Security-Token";
var AUTH_HEADER = "authorization";
var AMZ_DATE_HEADER = AMZ_DATE_QUERY_PARAM.toLowerCase();
var DATE_HEADER = "date";
var GENERATED_HEADERS = [AUTH_HEADER, AMZ_DATE_HEADER, DATE_HEADER];
var SIGNATURE_HEADER = SIGNATURE_QUERY_PARAM.toLowerCase();
var SHA256_HEADER = "x-amz-content-sha256";
var TOKEN_HEADER = TOKEN_QUERY_PARAM.toLowerCase();
var ALWAYS_UNSIGNABLE_HEADERS = {
  authorization: true,
  "cache-control": true,
  connection: true,
  expect: true,
  from: true,
  "keep-alive": true,
  "max-forwards": true,
  pragma: true,
  referer: true,
  te: true,
  trailer: true,
  "transfer-encoding": true,
  upgrade: true,
  "user-agent": true,
  "x-amzn-trace-id": true
};
var PROXY_HEADER_PATTERN = /^proxy-/;
var SEC_HEADER_PATTERN = /^sec-/;
var ALGORITHM_IDENTIFIER = "AWS4-HMAC-SHA256";
var EVENT_ALGORITHM_IDENTIFIER = "AWS4-HMAC-SHA256-PAYLOAD";
var UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
var MAX_CACHE_SIZE = 50;
var KEY_TYPE_IDENTIFIER = "aws4_request";
var MAX_PRESIGNED_TTL = 60 * 60 * 24 * 7;

// src/credentialDerivation.ts
var import_util_hex_encoding = __nccwpck_require__(5364);
var import_util_utf8 = __nccwpck_require__(1895);
var signingKeyCache = {};
var cacheQueue = [];
var createScope = /* @__PURE__ */ __name((shortDate, region, service) => `${shortDate}/${region}/${service}/${KEY_TYPE_IDENTIFIER}`, "createScope");
var getSigningKey = /* @__PURE__ */ __name(async (sha256Constructor, credentials, shortDate, region, service) => {
  const credsHash = await hmac(sha256Constructor, credentials.secretAccessKey, credentials.accessKeyId);
  const cacheKey = `${shortDate}:${region}:${service}:${(0, import_util_hex_encoding.toHex)(credsHash)}:${credentials.sessionToken}`;
  if (cacheKey in signingKeyCache) {
    return signingKeyCache[cacheKey];
  }
  cacheQueue.push(cacheKey);
  while (cacheQueue.length > MAX_CACHE_SIZE) {
    delete signingKeyCache[cacheQueue.shift()];
  }
  let key = `AWS4${credentials.secretAccessKey}`;
  for (const signable of [shortDate, region, service, KEY_TYPE_IDENTIFIER]) {
    key = await hmac(sha256Constructor, key, signable);
  }
  return signingKeyCache[cacheKey] = key;
}, "getSigningKey");
var clearCredentialCache = /* @__PURE__ */ __name(() => {
  cacheQueue.length = 0;
  Object.keys(signingKeyCache).forEach((cacheKey) => {
    delete signingKeyCache[cacheKey];
  });
}, "clearCredentialCache");
var hmac = /* @__PURE__ */ __name((ctor, secret, data) => {
  const hash = new ctor(secret);
  hash.update((0, import_util_utf8.toUint8Array)(data));
  return hash.digest();
}, "hmac");

// src/getCanonicalHeaders.ts
var getCanonicalHeaders = /* @__PURE__ */ __name(({ headers }, unsignableHeaders, signableHeaders) => {
  const canonical = {};
  for (const headerName of Object.keys(headers).sort()) {
    if (headers[headerName] == void 0) {
      continue;
    }
    const canonicalHeaderName = headerName.toLowerCase();
    if (canonicalHeaderName in ALWAYS_UNSIGNABLE_HEADERS || (unsignableHeaders == null ? void 0 : unsignableHeaders.has(canonicalHeaderName)) || PROXY_HEADER_PATTERN.test(canonicalHeaderName) || SEC_HEADER_PATTERN.test(canonicalHeaderName)) {
      if (!signableHeaders || signableHeaders && !signableHeaders.has(canonicalHeaderName)) {
        continue;
      }
    }
    canonical[canonicalHeaderName] = headers[headerName].trim().replace(/\s+/g, " ");
  }
  return canonical;
}, "getCanonicalHeaders");

// src/getCanonicalQuery.ts
var import_util_uri_escape = __nccwpck_require__(4197);
var getCanonicalQuery = /* @__PURE__ */ __name(({ query = {} }) => {
  const keys = [];
  const serialized = {};
  for (const key of Object.keys(query).sort()) {
    if (key.toLowerCase() === SIGNATURE_HEADER) {
      continue;
    }
    keys.push(key);
    const value = query[key];
    if (typeof value === "string") {
      serialized[key] = `${(0, import_util_uri_escape.escapeUri)(key)}=${(0, import_util_uri_escape.escapeUri)(value)}`;
    } else if (Array.isArray(value)) {
      serialized[key] = value.slice(0).reduce(
        (encoded, value2) => encoded.concat([`${(0, import_util_uri_escape.escapeUri)(key)}=${(0, import_util_uri_escape.escapeUri)(value2)}`]),
        []
      ).sort().join("&");
    }
  }
  return keys.map((key) => serialized[key]).filter((serialized2) => serialized2).join("&");
}, "getCanonicalQuery");

// src/getPayloadHash.ts
var import_is_array_buffer = __nccwpck_require__(780);

var import_util_utf82 = __nccwpck_require__(1895);
var getPayloadHash = /* @__PURE__ */ __name(async ({ headers, body }, hashConstructor) => {
  for (const headerName of Object.keys(headers)) {
    if (headerName.toLowerCase() === SHA256_HEADER) {
      return headers[headerName];
    }
  }
  if (body == void 0) {
    return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  } else if (typeof body === "string" || ArrayBuffer.isView(body) || (0, import_is_array_buffer.isArrayBuffer)(body)) {
    const hashCtor = new hashConstructor();
    hashCtor.update((0, import_util_utf82.toUint8Array)(body));
    return (0, import_util_hex_encoding.toHex)(await hashCtor.digest());
  }
  return UNSIGNED_PAYLOAD;
}, "getPayloadHash");

// src/HeaderFormatter.ts

var import_util_utf83 = __nccwpck_require__(1895);
var _HeaderFormatter = class _HeaderFormatter {
  format(headers) {
    const chunks = [];
    for (const headerName of Object.keys(headers)) {
      const bytes = (0, import_util_utf83.fromUtf8)(headerName);
      chunks.push(Uint8Array.from([bytes.byteLength]), bytes, this.formatHeaderValue(headers[headerName]));
    }
    const out = new Uint8Array(chunks.reduce((carry, bytes) => carry + bytes.byteLength, 0));
    let position = 0;
    for (const chunk of chunks) {
      out.set(chunk, position);
      position += chunk.byteLength;
    }
    return out;
  }
  formatHeaderValue(header) {
    switch (header.type) {
      case "boolean":
        return Uint8Array.from([header.value ? 0 /* boolTrue */ : 1 /* boolFalse */]);
      case "byte":
        return Uint8Array.from([2 /* byte */, header.value]);
      case "short":
        const shortView = new DataView(new ArrayBuffer(3));
        shortView.setUint8(0, 3 /* short */);
        shortView.setInt16(1, header.value, false);
        return new Uint8Array(shortView.buffer);
      case "integer":
        const intView = new DataView(new ArrayBuffer(5));
        intView.setUint8(0, 4 /* integer */);
        intView.setInt32(1, header.value, false);
        return new Uint8Array(intView.buffer);
      case "long":
        const longBytes = new Uint8Array(9);
        longBytes[0] = 5 /* long */;
        longBytes.set(header.value.bytes, 1);
        return longBytes;
      case "binary":
        const binView = new DataView(new ArrayBuffer(3 + header.value.byteLength));
        binView.setUint8(0, 6 /* byteArray */);
        binView.setUint16(1, header.value.byteLength, false);
        const binBytes = new Uint8Array(binView.buffer);
        binBytes.set(header.value, 3);
        return binBytes;
      case "string":
        const utf8Bytes = (0, import_util_utf83.fromUtf8)(header.value);
        const strView = new DataView(new ArrayBuffer(3 + utf8Bytes.byteLength));
        strView.setUint8(0, 7 /* string */);
        strView.setUint16(1, utf8Bytes.byteLength, false);
        const strBytes = new Uint8Array(strView.buffer);
        strBytes.set(utf8Bytes, 3);
        return strBytes;
      case "timestamp":
        const tsBytes = new Uint8Array(9);
        tsBytes[0] = 8 /* timestamp */;
        tsBytes.set(Int64.fromNumber(header.value.valueOf()).bytes, 1);
        return tsBytes;
      case "uuid":
        if (!UUID_PATTERN.test(header.value)) {
          throw new Error(`Invalid UUID received: ${header.value}`);
        }
        const uuidBytes = new Uint8Array(17);
        uuidBytes[0] = 9 /* uuid */;
        uuidBytes.set((0, import_util_hex_encoding.fromHex)(header.value.replace(/\-/g, "")), 1);
        return uuidBytes;
    }
  }
};
__name(_HeaderFormatter, "HeaderFormatter");
var HeaderFormatter = _HeaderFormatter;
var UUID_PATTERN = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
var _Int64 = class _Int64 {
  constructor(bytes) {
    this.bytes = bytes;
    if (bytes.byteLength !== 8) {
      throw new Error("Int64 buffers must be exactly 8 bytes");
    }
  }
  static fromNumber(number) {
    if (number > 9223372036854776e3 || number < -9223372036854776e3) {
      throw new Error(`${number} is too large (or, if negative, too small) to represent as an Int64`);
    }
    const bytes = new Uint8Array(8);
    for (let i = 7, remaining = Math.abs(Math.round(number)); i > -1 && remaining > 0; i--, remaining /= 256) {
      bytes[i] = remaining;
    }
    if (number < 0) {
      negate(bytes);
    }
    return new _Int64(bytes);
  }
  /**
   * Called implicitly by infix arithmetic operators.
   */
  valueOf() {
    const bytes = this.bytes.slice(0);
    const negative = bytes[0] & 128;
    if (negative) {
      negate(bytes);
    }
    return parseInt((0, import_util_hex_encoding.toHex)(bytes), 16) * (negative ? -1 : 1);
  }
  toString() {
    return String(this.valueOf());
  }
};
__name(_Int64, "Int64");
var Int64 = _Int64;
function negate(bytes) {
  for (let i = 0; i < 8; i++) {
    bytes[i] ^= 255;
  }
  for (let i = 7; i > -1; i--) {
    bytes[i]++;
    if (bytes[i] !== 0)
      break;
  }
}
__name(negate, "negate");

// src/headerUtil.ts
var hasHeader = /* @__PURE__ */ __name((soughtHeader, headers) => {
  soughtHeader = soughtHeader.toLowerCase();
  for (const headerName of Object.keys(headers)) {
    if (soughtHeader === headerName.toLowerCase()) {
      return true;
    }
  }
  return false;
}, "hasHeader");

// src/moveHeadersToQuery.ts
var import_protocol_http = __nccwpck_require__(4418);
var moveHeadersToQuery = /* @__PURE__ */ __name((request, options = {}) => {
  var _a;
  const { headers, query = {} } = import_protocol_http.HttpRequest.clone(request);
  for (const name of Object.keys(headers)) {
    const lname = name.toLowerCase();
    if (lname.slice(0, 6) === "x-amz-" && !((_a = options.unhoistableHeaders) == null ? void 0 : _a.has(lname))) {
      query[name] = headers[name];
      delete headers[name];
    }
  }
  return {
    ...request,
    headers,
    query
  };
}, "moveHeadersToQuery");

// src/prepareRequest.ts

var prepareRequest = /* @__PURE__ */ __name((request) => {
  request = import_protocol_http.HttpRequest.clone(request);
  for (const headerName of Object.keys(request.headers)) {
    if (GENERATED_HEADERS.indexOf(headerName.toLowerCase()) > -1) {
      delete request.headers[headerName];
    }
  }
  return request;
}, "prepareRequest");

// src/utilDate.ts
var iso8601 = /* @__PURE__ */ __name((time) => toDate(time).toISOString().replace(/\.\d{3}Z$/, "Z"), "iso8601");
var toDate = /* @__PURE__ */ __name((time) => {
  if (typeof time === "number") {
    return new Date(time * 1e3);
  }
  if (typeof time === "string") {
    if (Number(time)) {
      return new Date(Number(time) * 1e3);
    }
    return new Date(time);
  }
  return time;
}, "toDate");

// src/SignatureV4.ts
var _SignatureV4 = class _SignatureV4 {
  constructor({
    applyChecksum,
    credentials,
    region,
    service,
    sha256,
    uriEscapePath = true
  }) {
    this.headerFormatter = new HeaderFormatter();
    this.service = service;
    this.sha256 = sha256;
    this.uriEscapePath = uriEscapePath;
    this.applyChecksum = typeof applyChecksum === "boolean" ? applyChecksum : true;
    this.regionProvider = (0, import_util_middleware.normalizeProvider)(region);
    this.credentialProvider = (0, import_util_middleware.normalizeProvider)(credentials);
  }
  async presign(originalRequest, options = {}) {
    const {
      signingDate = /* @__PURE__ */ new Date(),
      expiresIn = 3600,
      unsignableHeaders,
      unhoistableHeaders,
      signableHeaders,
      signingRegion,
      signingService
    } = options;
    const credentials = await this.credentialProvider();
    this.validateResolvedCredentials(credentials);
    const region = signingRegion ?? await this.regionProvider();
    const { longDate, shortDate } = formatDate(signingDate);
    if (expiresIn > MAX_PRESIGNED_TTL) {
      return Promise.reject(
        "Signature version 4 presigned URLs must have an expiration date less than one week in the future"
      );
    }
    const scope = createScope(shortDate, region, signingService ?? this.service);
    const request = moveHeadersToQuery(prepareRequest(originalRequest), { unhoistableHeaders });
    if (credentials.sessionToken) {
      request.query[TOKEN_QUERY_PARAM] = credentials.sessionToken;
    }
    request.query[ALGORITHM_QUERY_PARAM] = ALGORITHM_IDENTIFIER;
    request.query[CREDENTIAL_QUERY_PARAM] = `${credentials.accessKeyId}/${scope}`;
    request.query[AMZ_DATE_QUERY_PARAM] = longDate;
    request.query[EXPIRES_QUERY_PARAM] = expiresIn.toString(10);
    const canonicalHeaders = getCanonicalHeaders(request, unsignableHeaders, signableHeaders);
    request.query[SIGNED_HEADERS_QUERY_PARAM] = getCanonicalHeaderList(canonicalHeaders);
    request.query[SIGNATURE_QUERY_PARAM] = await this.getSignature(
      longDate,
      scope,
      this.getSigningKey(credentials, region, shortDate, signingService),
      this.createCanonicalRequest(request, canonicalHeaders, await getPayloadHash(originalRequest, this.sha256))
    );
    return request;
  }
  async sign(toSign, options) {
    if (typeof toSign === "string") {
      return this.signString(toSign, options);
    } else if (toSign.headers && toSign.payload) {
      return this.signEvent(toSign, options);
    } else if (toSign.message) {
      return this.signMessage(toSign, options);
    } else {
      return this.signRequest(toSign, options);
    }
  }
  async signEvent({ headers, payload }, { signingDate = /* @__PURE__ */ new Date(), priorSignature, signingRegion, signingService }) {
    const region = signingRegion ?? await this.regionProvider();
    const { shortDate, longDate } = formatDate(signingDate);
    const scope = createScope(shortDate, region, signingService ?? this.service);
    const hashedPayload = await getPayloadHash({ headers: {}, body: payload }, this.sha256);
    const hash = new this.sha256();
    hash.update(headers);
    const hashedHeaders = (0, import_util_hex_encoding.toHex)(await hash.digest());
    const stringToSign = [
      EVENT_ALGORITHM_IDENTIFIER,
      longDate,
      scope,
      priorSignature,
      hashedHeaders,
      hashedPayload
    ].join("\n");
    return this.signString(stringToSign, { signingDate, signingRegion: region, signingService });
  }
  async signMessage(signableMessage, { signingDate = /* @__PURE__ */ new Date(), signingRegion, signingService }) {
    const promise = this.signEvent(
      {
        headers: this.headerFormatter.format(signableMessage.message.headers),
        payload: signableMessage.message.body
      },
      {
        signingDate,
        signingRegion,
        signingService,
        priorSignature: signableMessage.priorSignature
      }
    );
    return promise.then((signature) => {
      return { message: signableMessage.message, signature };
    });
  }
  async signString(stringToSign, { signingDate = /* @__PURE__ */ new Date(), signingRegion, signingService } = {}) {
    const credentials = await this.credentialProvider();
    this.validateResolvedCredentials(credentials);
    const region = signingRegion ?? await this.regionProvider();
    const { shortDate } = formatDate(signingDate);
    const hash = new this.sha256(await this.getSigningKey(credentials, region, shortDate, signingService));
    hash.update((0, import_util_utf84.toUint8Array)(stringToSign));
    return (0, import_util_hex_encoding.toHex)(await hash.digest());
  }
  async signRequest(requestToSign, {
    signingDate = /* @__PURE__ */ new Date(),
    signableHeaders,
    unsignableHeaders,
    signingRegion,
    signingService
  } = {}) {
    const credentials = await this.credentialProvider();
    this.validateResolvedCredentials(credentials);
    const region = signingRegion ?? await this.regionProvider();
    const request = prepareRequest(requestToSign);
    const { longDate, shortDate } = formatDate(signingDate);
    const scope = createScope(shortDate, region, signingService ?? this.service);
    request.headers[AMZ_DATE_HEADER] = longDate;
    if (credentials.sessionToken) {
      request.headers[TOKEN_HEADER] = credentials.sessionToken;
    }
    const payloadHash = await getPayloadHash(request, this.sha256);
    if (!hasHeader(SHA256_HEADER, request.headers) && this.applyChecksum) {
      request.headers[SHA256_HEADER] = payloadHash;
    }
    const canonicalHeaders = getCanonicalHeaders(request, unsignableHeaders, signableHeaders);
    const signature = await this.getSignature(
      longDate,
      scope,
      this.getSigningKey(credentials, region, shortDate, signingService),
      this.createCanonicalRequest(request, canonicalHeaders, payloadHash)
    );
    request.headers[AUTH_HEADER] = `${ALGORITHM_IDENTIFIER} Credential=${credentials.accessKeyId}/${scope}, SignedHeaders=${getCanonicalHeaderList(canonicalHeaders)}, Signature=${signature}`;
    return request;
  }
  createCanonicalRequest(request, canonicalHeaders, payloadHash) {
    const sortedHeaders = Object.keys(canonicalHeaders).sort();
    return `${request.method}
${this.getCanonicalPath(request)}
${getCanonicalQuery(request)}
${sortedHeaders.map((name) => `${name}:${canonicalHeaders[name]}`).join("\n")}

${sortedHeaders.join(";")}
${payloadHash}`;
  }
  async createStringToSign(longDate, credentialScope, canonicalRequest) {
    const hash = new this.sha256();
    hash.update((0, import_util_utf84.toUint8Array)(canonicalRequest));
    const hashedRequest = await hash.digest();
    return `${ALGORITHM_IDENTIFIER}
${longDate}
${credentialScope}
${(0, import_util_hex_encoding.toHex)(hashedRequest)}`;
  }
  getCanonicalPath({ path }) {
    if (this.uriEscapePath) {
      const normalizedPathSegments = [];
      for (const pathSegment of path.split("/")) {
        if ((pathSegment == null ? void 0 : pathSegment.length) === 0)
          continue;
        if (pathSegment === ".")
          continue;
        if (pathSegment === "..") {
          normalizedPathSegments.pop();
        } else {
          normalizedPathSegments.push(pathSegment);
        }
      }
      const normalizedPath = `${(path == null ? void 0 : path.startsWith("/")) ? "/" : ""}${normalizedPathSegments.join("/")}${normalizedPathSegments.length > 0 && (path == null ? void 0 : path.endsWith("/")) ? "/" : ""}`;
      const doubleEncoded = (0, import_util_uri_escape.escapeUri)(normalizedPath);
      return doubleEncoded.replace(/%2F/g, "/");
    }
    return path;
  }
  async getSignature(longDate, credentialScope, keyPromise, canonicalRequest) {
    const stringToSign = await this.createStringToSign(longDate, credentialScope, canonicalRequest);
    const hash = new this.sha256(await keyPromise);
    hash.update((0, import_util_utf84.toUint8Array)(stringToSign));
    return (0, import_util_hex_encoding.toHex)(await hash.digest());
  }
  getSigningKey(credentials, region, shortDate, service) {
    return getSigningKey(this.sha256, credentials, shortDate, region, service || this.service);
  }
  validateResolvedCredentials(credentials) {
    if (typeof credentials !== "object" || // @ts-expect-error: Property 'accessKeyId' does not exist on type 'object'.ts(2339)
    typeof credentials.accessKeyId !== "string" || // @ts-expect-error: Property 'secretAccessKey' does not exist on type 'object'.ts(2339)
    typeof credentials.secretAccessKey !== "string") {
      throw new Error("Resolved credential object is not valid");
    }
  }
};
__name(_SignatureV4, "SignatureV4");
var SignatureV4 = _SignatureV4;
var formatDate = /* @__PURE__ */ __name((now) => {
  const longDate = iso8601(now).replace(/[\-:]/g, "");
  return {
    longDate,
    shortDate: longDate.slice(0, 8)
  };
}, "formatDate");
var getCanonicalHeaderList = /* @__PURE__ */ __name((headers) => Object.keys(headers).sort().join(";"), "getCanonicalHeaderList");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 3570:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  Client: () => Client,
  Command: () => Command,
  LazyJsonString: () => LazyJsonString,
  NoOpLogger: () => NoOpLogger,
  SENSITIVE_STRING: () => SENSITIVE_STRING,
  ServiceException: () => ServiceException,
  StringWrapper: () => StringWrapper,
  _json: () => _json,
  collectBody: () => collectBody,
  convertMap: () => convertMap,
  createAggregatedClient: () => createAggregatedClient,
  dateToUtcString: () => dateToUtcString,
  decorateServiceException: () => decorateServiceException,
  emitWarningIfUnsupportedVersion: () => emitWarningIfUnsupportedVersion,
  expectBoolean: () => expectBoolean,
  expectByte: () => expectByte,
  expectFloat32: () => expectFloat32,
  expectInt: () => expectInt,
  expectInt32: () => expectInt32,
  expectLong: () => expectLong,
  expectNonNull: () => expectNonNull,
  expectNumber: () => expectNumber,
  expectObject: () => expectObject,
  expectShort: () => expectShort,
  expectString: () => expectString,
  expectUnion: () => expectUnion,
  extendedEncodeURIComponent: () => extendedEncodeURIComponent,
  getArrayIfSingleItem: () => getArrayIfSingleItem,
  getDefaultClientConfiguration: () => getDefaultClientConfiguration,
  getDefaultExtensionConfiguration: () => getDefaultExtensionConfiguration,
  getValueFromTextNode: () => getValueFromTextNode,
  handleFloat: () => handleFloat,
  limitedParseDouble: () => limitedParseDouble,
  limitedParseFloat: () => limitedParseFloat,
  limitedParseFloat32: () => limitedParseFloat32,
  loadConfigsForDefaultMode: () => loadConfigsForDefaultMode,
  logger: () => logger,
  map: () => map,
  parseBoolean: () => parseBoolean,
  parseEpochTimestamp: () => parseEpochTimestamp,
  parseRfc3339DateTime: () => parseRfc3339DateTime,
  parseRfc3339DateTimeWithOffset: () => parseRfc3339DateTimeWithOffset,
  parseRfc7231DateTime: () => parseRfc7231DateTime,
  resolveDefaultRuntimeConfig: () => resolveDefaultRuntimeConfig,
  resolvedPath: () => resolvedPath,
  serializeDateTime: () => serializeDateTime,
  serializeFloat: () => serializeFloat,
  splitEvery: () => splitEvery,
  strictParseByte: () => strictParseByte,
  strictParseDouble: () => strictParseDouble,
  strictParseFloat: () => strictParseFloat,
  strictParseFloat32: () => strictParseFloat32,
  strictParseInt: () => strictParseInt,
  strictParseInt32: () => strictParseInt32,
  strictParseLong: () => strictParseLong,
  strictParseShort: () => strictParseShort,
  take: () => take,
  throwDefaultError: () => throwDefaultError,
  withBaseException: () => withBaseException
});
module.exports = __toCommonJS(src_exports);

// src/NoOpLogger.ts
var _NoOpLogger = class _NoOpLogger {
  trace() {
  }
  debug() {
  }
  info() {
  }
  warn() {
  }
  error() {
  }
};
__name(_NoOpLogger, "NoOpLogger");
var NoOpLogger = _NoOpLogger;

// src/client.ts
var import_middleware_stack = __nccwpck_require__(7911);
var _Client = class _Client {
  constructor(config) {
    this.middlewareStack = (0, import_middleware_stack.constructStack)();
    this.config = config;
  }
  send(command, optionsOrCb, cb) {
    const options = typeof optionsOrCb !== "function" ? optionsOrCb : void 0;
    const callback = typeof optionsOrCb === "function" ? optionsOrCb : cb;
    const handler = command.resolveMiddleware(this.middlewareStack, this.config, options);
    if (callback) {
      handler(command).then(
        (result) => callback(null, result.output),
        (err) => callback(err)
      ).catch(
        // prevent any errors thrown in the callback from triggering an
        // unhandled promise rejection
        () => {
        }
      );
    } else {
      return handler(command).then((result) => result.output);
    }
  }
  destroy() {
    if (this.config.requestHandler.destroy)
      this.config.requestHandler.destroy();
  }
};
__name(_Client, "Client");
var Client = _Client;

// src/collect-stream-body.ts
var import_util_stream = __nccwpck_require__(6607);
var collectBody = /* @__PURE__ */ __name(async (streamBody = new Uint8Array(), context) => {
  if (streamBody instanceof Uint8Array) {
    return import_util_stream.Uint8ArrayBlobAdapter.mutate(streamBody);
  }
  if (!streamBody) {
    return import_util_stream.Uint8ArrayBlobAdapter.mutate(new Uint8Array());
  }
  const fromContext = context.streamCollector(streamBody);
  return import_util_stream.Uint8ArrayBlobAdapter.mutate(await fromContext);
}, "collectBody");

// src/command.ts

var import_types = __nccwpck_require__(5756);
var _Command = class _Command {
  constructor() {
    this.middlewareStack = (0, import_middleware_stack.constructStack)();
  }
  /**
   * Factory for Command ClassBuilder.
   * @internal
   */
  static classBuilder() {
    return new ClassBuilder();
  }
  /**
   * @internal
   */
  resolveMiddlewareWithContext(clientStack, configuration, options, {
    middlewareFn,
    clientName,
    commandName,
    inputFilterSensitiveLog,
    outputFilterSensitiveLog,
    smithyContext,
    additionalContext,
    CommandCtor
  }) {
    for (const mw of middlewareFn.bind(this)(CommandCtor, clientStack, configuration, options)) {
      this.middlewareStack.use(mw);
    }
    const stack = clientStack.concat(this.middlewareStack);
    const { logger: logger2 } = configuration;
    const handlerExecutionContext = {
      logger: logger2,
      clientName,
      commandName,
      inputFilterSensitiveLog,
      outputFilterSensitiveLog,
      [import_types.SMITHY_CONTEXT_KEY]: {
        commandInstance: this,
        ...smithyContext
      },
      ...additionalContext
    };
    const { requestHandler } = configuration;
    return stack.resolve(
      (request) => requestHandler.handle(request.request, options || {}),
      handlerExecutionContext
    );
  }
};
__name(_Command, "Command");
var Command = _Command;
var _ClassBuilder = class _ClassBuilder {
  constructor() {
    this._init = () => {
    };
    this._ep = {};
    this._middlewareFn = () => [];
    this._commandName = "";
    this._clientName = "";
    this._additionalContext = {};
    this._smithyContext = {};
    this._inputFilterSensitiveLog = (_) => _;
    this._outputFilterSensitiveLog = (_) => _;
    this._serializer = null;
    this._deserializer = null;
  }
  /**
   * Optional init callback.
   */
  init(cb) {
    this._init = cb;
  }
  /**
   * Set the endpoint parameter instructions.
   */
  ep(endpointParameterInstructions) {
    this._ep = endpointParameterInstructions;
    return this;
  }
  /**
   * Add any number of middleware.
   */
  m(middlewareSupplier) {
    this._middlewareFn = middlewareSupplier;
    return this;
  }
  /**
   * Set the initial handler execution context Smithy field.
   */
  s(service, operation, smithyContext = {}) {
    this._smithyContext = {
      service,
      operation,
      ...smithyContext
    };
    return this;
  }
  /**
   * Set the initial handler execution context.
   */
  c(additionalContext = {}) {
    this._additionalContext = additionalContext;
    return this;
  }
  /**
   * Set constant string identifiers for the operation.
   */
  n(clientName, commandName) {
    this._clientName = clientName;
    this._commandName = commandName;
    return this;
  }
  /**
   * Set the input and output sensistive log filters.
   */
  f(inputFilter = (_) => _, outputFilter = (_) => _) {
    this._inputFilterSensitiveLog = inputFilter;
    this._outputFilterSensitiveLog = outputFilter;
    return this;
  }
  /**
   * Sets the serializer.
   */
  ser(serializer) {
    this._serializer = serializer;
    return this;
  }
  /**
   * Sets the deserializer.
   */
  de(deserializer) {
    this._deserializer = deserializer;
    return this;
  }
  /**
   * @returns a Command class with the classBuilder properties.
   */
  build() {
    var _a;
    const closure = this;
    let CommandRef;
    return CommandRef = (_a = class extends Command {
      /**
       * @public
       */
      constructor(...[input]) {
        super();
        /**
         * @internal
         */
        // @ts-ignore used in middlewareFn closure.
        this.serialize = closure._serializer;
        /**
         * @internal
         */
        // @ts-ignore used in middlewareFn closure.
        this.deserialize = closure._deserializer;
        this.input = input ?? {};
        closure._init(this);
      }
      /**
       * @public
       */
      static getEndpointParameterInstructions() {
        return closure._ep;
      }
      /**
       * @internal
       */
      resolveMiddleware(stack, configuration, options) {
        return this.resolveMiddlewareWithContext(stack, configuration, options, {
          CommandCtor: CommandRef,
          middlewareFn: closure._middlewareFn,
          clientName: closure._clientName,
          commandName: closure._commandName,
          inputFilterSensitiveLog: closure._inputFilterSensitiveLog,
          outputFilterSensitiveLog: closure._outputFilterSensitiveLog,
          smithyContext: closure._smithyContext,
          additionalContext: closure._additionalContext
        });
      }
    }, __name(_a, "CommandRef"), _a);
  }
};
__name(_ClassBuilder, "ClassBuilder");
var ClassBuilder = _ClassBuilder;

// src/constants.ts
var SENSITIVE_STRING = "***SensitiveInformation***";

// src/create-aggregated-client.ts
var createAggregatedClient = /* @__PURE__ */ __name((commands, Client2) => {
  for (const command of Object.keys(commands)) {
    const CommandCtor = commands[command];
    const methodImpl = /* @__PURE__ */ __name(async function(args, optionsOrCb, cb) {
      const command2 = new CommandCtor(args);
      if (typeof optionsOrCb === "function") {
        this.send(command2, optionsOrCb);
      } else if (typeof cb === "function") {
        if (typeof optionsOrCb !== "object")
          throw new Error(`Expected http options but got ${typeof optionsOrCb}`);
        this.send(command2, optionsOrCb || {}, cb);
      } else {
        return this.send(command2, optionsOrCb);
      }
    }, "methodImpl");
    const methodName = (command[0].toLowerCase() + command.slice(1)).replace(/Command$/, "");
    Client2.prototype[methodName] = methodImpl;
  }
}, "createAggregatedClient");

// src/parse-utils.ts
var parseBoolean = /* @__PURE__ */ __name((value) => {
  switch (value) {
    case "true":
      return true;
    case "false":
      return false;
    default:
      throw new Error(`Unable to parse boolean value "${value}"`);
  }
}, "parseBoolean");
var expectBoolean = /* @__PURE__ */ __name((value) => {
  if (value === null || value === void 0) {
    return void 0;
  }
  if (typeof value === "number") {
    if (value === 0 || value === 1) {
      logger.warn(stackTraceWarning(`Expected boolean, got ${typeof value}: ${value}`));
    }
    if (value === 0) {
      return false;
    }
    if (value === 1) {
      return true;
    }
  }
  if (typeof value === "string") {
    const lower = value.toLowerCase();
    if (lower === "false" || lower === "true") {
      logger.warn(stackTraceWarning(`Expected boolean, got ${typeof value}: ${value}`));
    }
    if (lower === "false") {
      return false;
    }
    if (lower === "true") {
      return true;
    }
  }
  if (typeof value === "boolean") {
    return value;
  }
  throw new TypeError(`Expected boolean, got ${typeof value}: ${value}`);
}, "expectBoolean");
var expectNumber = /* @__PURE__ */ __name((value) => {
  if (value === null || value === void 0) {
    return void 0;
  }
  if (typeof value === "string") {
    const parsed = parseFloat(value);
    if (!Number.isNaN(parsed)) {
      if (String(parsed) !== String(value)) {
        logger.warn(stackTraceWarning(`Expected number but observed string: ${value}`));
      }
      return parsed;
    }
  }
  if (typeof value === "number") {
    return value;
  }
  throw new TypeError(`Expected number, got ${typeof value}: ${value}`);
}, "expectNumber");
var MAX_FLOAT = Math.ceil(2 ** 127 * (2 - 2 ** -23));
var expectFloat32 = /* @__PURE__ */ __name((value) => {
  const expected = expectNumber(value);
  if (expected !== void 0 && !Number.isNaN(expected) && expected !== Infinity && expected !== -Infinity) {
    if (Math.abs(expected) > MAX_FLOAT) {
      throw new TypeError(`Expected 32-bit float, got ${value}`);
    }
  }
  return expected;
}, "expectFloat32");
var expectLong = /* @__PURE__ */ __name((value) => {
  if (value === null || value === void 0) {
    return void 0;
  }
  if (Number.isInteger(value) && !Number.isNaN(value)) {
    return value;
  }
  throw new TypeError(`Expected integer, got ${typeof value}: ${value}`);
}, "expectLong");
var expectInt = expectLong;
var expectInt32 = /* @__PURE__ */ __name((value) => expectSizedInt(value, 32), "expectInt32");
var expectShort = /* @__PURE__ */ __name((value) => expectSizedInt(value, 16), "expectShort");
var expectByte = /* @__PURE__ */ __name((value) => expectSizedInt(value, 8), "expectByte");
var expectSizedInt = /* @__PURE__ */ __name((value, size) => {
  const expected = expectLong(value);
  if (expected !== void 0 && castInt(expected, size) !== expected) {
    throw new TypeError(`Expected ${size}-bit integer, got ${value}`);
  }
  return expected;
}, "expectSizedInt");
var castInt = /* @__PURE__ */ __name((value, size) => {
  switch (size) {
    case 32:
      return Int32Array.of(value)[0];
    case 16:
      return Int16Array.of(value)[0];
    case 8:
      return Int8Array.of(value)[0];
  }
}, "castInt");
var expectNonNull = /* @__PURE__ */ __name((value, location) => {
  if (value === null || value === void 0) {
    if (location) {
      throw new TypeError(`Expected a non-null value for ${location}`);
    }
    throw new TypeError("Expected a non-null value");
  }
  return value;
}, "expectNonNull");
var expectObject = /* @__PURE__ */ __name((value) => {
  if (value === null || value === void 0) {
    return void 0;
  }
  if (typeof value === "object" && !Array.isArray(value)) {
    return value;
  }
  const receivedType = Array.isArray(value) ? "array" : typeof value;
  throw new TypeError(`Expected object, got ${receivedType}: ${value}`);
}, "expectObject");
var expectString = /* @__PURE__ */ __name((value) => {
  if (value === null || value === void 0) {
    return void 0;
  }
  if (typeof value === "string") {
    return value;
  }
  if (["boolean", "number", "bigint"].includes(typeof value)) {
    logger.warn(stackTraceWarning(`Expected string, got ${typeof value}: ${value}`));
    return String(value);
  }
  throw new TypeError(`Expected string, got ${typeof value}: ${value}`);
}, "expectString");
var expectUnion = /* @__PURE__ */ __name((value) => {
  if (value === null || value === void 0) {
    return void 0;
  }
  const asObject = expectObject(value);
  const setKeys = Object.entries(asObject).filter(([, v]) => v != null).map(([k]) => k);
  if (setKeys.length === 0) {
    throw new TypeError(`Unions must have exactly one non-null member. None were found.`);
  }
  if (setKeys.length > 1) {
    throw new TypeError(`Unions must have exactly one non-null member. Keys ${setKeys} were not null.`);
  }
  return asObject;
}, "expectUnion");
var strictParseDouble = /* @__PURE__ */ __name((value) => {
  if (typeof value == "string") {
    return expectNumber(parseNumber(value));
  }
  return expectNumber(value);
}, "strictParseDouble");
var strictParseFloat = strictParseDouble;
var strictParseFloat32 = /* @__PURE__ */ __name((value) => {
  if (typeof value == "string") {
    return expectFloat32(parseNumber(value));
  }
  return expectFloat32(value);
}, "strictParseFloat32");
var NUMBER_REGEX = /(-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)|(-?Infinity)|(NaN)/g;
var parseNumber = /* @__PURE__ */ __name((value) => {
  const matches = value.match(NUMBER_REGEX);
  if (matches === null || matches[0].length !== value.length) {
    throw new TypeError(`Expected real number, got implicit NaN`);
  }
  return parseFloat(value);
}, "parseNumber");
var limitedParseDouble = /* @__PURE__ */ __name((value) => {
  if (typeof value == "string") {
    return parseFloatString(value);
  }
  return expectNumber(value);
}, "limitedParseDouble");
var handleFloat = limitedParseDouble;
var limitedParseFloat = limitedParseDouble;
var limitedParseFloat32 = /* @__PURE__ */ __name((value) => {
  if (typeof value == "string") {
    return parseFloatString(value);
  }
  return expectFloat32(value);
}, "limitedParseFloat32");
var parseFloatString = /* @__PURE__ */ __name((value) => {
  switch (value) {
    case "NaN":
      return NaN;
    case "Infinity":
      return Infinity;
    case "-Infinity":
      return -Infinity;
    default:
      throw new Error(`Unable to parse float value: ${value}`);
  }
}, "parseFloatString");
var strictParseLong = /* @__PURE__ */ __name((value) => {
  if (typeof value === "string") {
    return expectLong(parseNumber(value));
  }
  return expectLong(value);
}, "strictParseLong");
var strictParseInt = strictParseLong;
var strictParseInt32 = /* @__PURE__ */ __name((value) => {
  if (typeof value === "string") {
    return expectInt32(parseNumber(value));
  }
  return expectInt32(value);
}, "strictParseInt32");
var strictParseShort = /* @__PURE__ */ __name((value) => {
  if (typeof value === "string") {
    return expectShort(parseNumber(value));
  }
  return expectShort(value);
}, "strictParseShort");
var strictParseByte = /* @__PURE__ */ __name((value) => {
  if (typeof value === "string") {
    return expectByte(parseNumber(value));
  }
  return expectByte(value);
}, "strictParseByte");
var stackTraceWarning = /* @__PURE__ */ __name((message) => {
  return String(new TypeError(message).stack || message).split("\n").slice(0, 5).filter((s) => !s.includes("stackTraceWarning")).join("\n");
}, "stackTraceWarning");
var logger = {
  warn: console.warn
};

// src/date-utils.ts
var DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
var MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
function dateToUtcString(date) {
  const year = date.getUTCFullYear();
  const month = date.getUTCMonth();
  const dayOfWeek = date.getUTCDay();
  const dayOfMonthInt = date.getUTCDate();
  const hoursInt = date.getUTCHours();
  const minutesInt = date.getUTCMinutes();
  const secondsInt = date.getUTCSeconds();
  const dayOfMonthString = dayOfMonthInt < 10 ? `0${dayOfMonthInt}` : `${dayOfMonthInt}`;
  const hoursString = hoursInt < 10 ? `0${hoursInt}` : `${hoursInt}`;
  const minutesString = minutesInt < 10 ? `0${minutesInt}` : `${minutesInt}`;
  const secondsString = secondsInt < 10 ? `0${secondsInt}` : `${secondsInt}`;
  return `${DAYS[dayOfWeek]}, ${dayOfMonthString} ${MONTHS[month]} ${year} ${hoursString}:${minutesString}:${secondsString} GMT`;
}
__name(dateToUtcString, "dateToUtcString");
var RFC3339 = new RegExp(/^(\d{4})-(\d{2})-(\d{2})[tT](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?[zZ]$/);
var parseRfc3339DateTime = /* @__PURE__ */ __name((value) => {
  if (value === null || value === void 0) {
    return void 0;
  }
  if (typeof value !== "string") {
    throw new TypeError("RFC-3339 date-times must be expressed as strings");
  }
  const match = RFC3339.exec(value);
  if (!match) {
    throw new TypeError("Invalid RFC-3339 date-time value");
  }
  const [_, yearStr, monthStr, dayStr, hours, minutes, seconds, fractionalMilliseconds] = match;
  const year = strictParseShort(stripLeadingZeroes(yearStr));
  const month = parseDateValue(monthStr, "month", 1, 12);
  const day = parseDateValue(dayStr, "day", 1, 31);
  return buildDate(year, month, day, { hours, minutes, seconds, fractionalMilliseconds });
}, "parseRfc3339DateTime");
var RFC3339_WITH_OFFSET = new RegExp(
  /^(\d{4})-(\d{2})-(\d{2})[tT](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(([-+]\d{2}\:\d{2})|[zZ])$/
);
var parseRfc3339DateTimeWithOffset = /* @__PURE__ */ __name((value) => {
  if (value === null || value === void 0) {
    return void 0;
  }
  if (typeof value !== "string") {
    throw new TypeError("RFC-3339 date-times must be expressed as strings");
  }
  const match = RFC3339_WITH_OFFSET.exec(value);
  if (!match) {
    throw new TypeError("Invalid RFC-3339 date-time value");
  }
  const [_, yearStr, monthStr, dayStr, hours, minutes, seconds, fractionalMilliseconds, offsetStr] = match;
  const year = strictParseShort(stripLeadingZeroes(yearStr));
  const month = parseDateValue(monthStr, "month", 1, 12);
  const day = parseDateValue(dayStr, "day", 1, 31);
  const date = buildDate(year, month, day, { hours, minutes, seconds, fractionalMilliseconds });
  if (offsetStr.toUpperCase() != "Z") {
    date.setTime(date.getTime() - parseOffsetToMilliseconds(offsetStr));
  }
  return date;
}, "parseRfc3339DateTimeWithOffset");
var IMF_FIXDATE = new RegExp(
  /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), (\d{2}) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (\d{4}) (\d{1,2}):(\d{2}):(\d{2})(?:\.(\d+))? GMT$/
);
var RFC_850_DATE = new RegExp(
  /^(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), (\d{2})-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-(\d{2}) (\d{1,2}):(\d{2}):(\d{2})(?:\.(\d+))? GMT$/
);
var ASC_TIME = new RegExp(
  /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ( [1-9]|\d{2}) (\d{1,2}):(\d{2}):(\d{2})(?:\.(\d+))? (\d{4})$/
);
var parseRfc7231DateTime = /* @__PURE__ */ __name((value) => {
  if (value === null || value === void 0) {
    return void 0;
  }
  if (typeof value !== "string") {
    throw new TypeError("RFC-7231 date-times must be expressed as strings");
  }
  let match = IMF_FIXDATE.exec(value);
  if (match) {
    const [_, dayStr, monthStr, yearStr, hours, minutes, seconds, fractionalMilliseconds] = match;
    return buildDate(
      strictParseShort(stripLeadingZeroes(yearStr)),
      parseMonthByShortName(monthStr),
      parseDateValue(dayStr, "day", 1, 31),
      { hours, minutes, seconds, fractionalMilliseconds }
    );
  }
  match = RFC_850_DATE.exec(value);
  if (match) {
    const [_, dayStr, monthStr, yearStr, hours, minutes, seconds, fractionalMilliseconds] = match;
    return adjustRfc850Year(
      buildDate(parseTwoDigitYear(yearStr), parseMonthByShortName(monthStr), parseDateValue(dayStr, "day", 1, 31), {
        hours,
        minutes,
        seconds,
        fractionalMilliseconds
      })
    );
  }
  match = ASC_TIME.exec(value);
  if (match) {
    const [_, monthStr, dayStr, hours, minutes, seconds, fractionalMilliseconds, yearStr] = match;
    return buildDate(
      strictParseShort(stripLeadingZeroes(yearStr)),
      parseMonthByShortName(monthStr),
      parseDateValue(dayStr.trimLeft(), "day", 1, 31),
      { hours, minutes, seconds, fractionalMilliseconds }
    );
  }
  throw new TypeError("Invalid RFC-7231 date-time value");
}, "parseRfc7231DateTime");
var parseEpochTimestamp = /* @__PURE__ */ __name((value) => {
  if (value === null || value === void 0) {
    return void 0;
  }
  let valueAsDouble;
  if (typeof value === "number") {
    valueAsDouble = value;
  } else if (typeof value === "string") {
    valueAsDouble = strictParseDouble(value);
  } else {
    throw new TypeError("Epoch timestamps must be expressed as floating point numbers or their string representation");
  }
  if (Number.isNaN(valueAsDouble) || valueAsDouble === Infinity || valueAsDouble === -Infinity) {
    throw new TypeError("Epoch timestamps must be valid, non-Infinite, non-NaN numerics");
  }
  return new Date(Math.round(valueAsDouble * 1e3));
}, "parseEpochTimestamp");
var buildDate = /* @__PURE__ */ __name((year, month, day, time) => {
  const adjustedMonth = month - 1;
  validateDayOfMonth(year, adjustedMonth, day);
  return new Date(
    Date.UTC(
      year,
      adjustedMonth,
      day,
      parseDateValue(time.hours, "hour", 0, 23),
      parseDateValue(time.minutes, "minute", 0, 59),
      // seconds can go up to 60 for leap seconds
      parseDateValue(time.seconds, "seconds", 0, 60),
      parseMilliseconds(time.fractionalMilliseconds)
    )
  );
}, "buildDate");
var parseTwoDigitYear = /* @__PURE__ */ __name((value) => {
  const thisYear = (/* @__PURE__ */ new Date()).getUTCFullYear();
  const valueInThisCentury = Math.floor(thisYear / 100) * 100 + strictParseShort(stripLeadingZeroes(value));
  if (valueInThisCentury < thisYear) {
    return valueInThisCentury + 100;
  }
  return valueInThisCentury;
}, "parseTwoDigitYear");
var FIFTY_YEARS_IN_MILLIS = 50 * 365 * 24 * 60 * 60 * 1e3;
var adjustRfc850Year = /* @__PURE__ */ __name((input) => {
  if (input.getTime() - (/* @__PURE__ */ new Date()).getTime() > FIFTY_YEARS_IN_MILLIS) {
    return new Date(
      Date.UTC(
        input.getUTCFullYear() - 100,
        input.getUTCMonth(),
        input.getUTCDate(),
        input.getUTCHours(),
        input.getUTCMinutes(),
        input.getUTCSeconds(),
        input.getUTCMilliseconds()
      )
    );
  }
  return input;
}, "adjustRfc850Year");
var parseMonthByShortName = /* @__PURE__ */ __name((value) => {
  const monthIdx = MONTHS.indexOf(value);
  if (monthIdx < 0) {
    throw new TypeError(`Invalid month: ${value}`);
  }
  return monthIdx + 1;
}, "parseMonthByShortName");
var DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
var validateDayOfMonth = /* @__PURE__ */ __name((year, month, day) => {
  let maxDays = DAYS_IN_MONTH[month];
  if (month === 1 && isLeapYear(year)) {
    maxDays = 29;
  }
  if (day > maxDays) {
    throw new TypeError(`Invalid day for ${MONTHS[month]} in ${year}: ${day}`);
  }
}, "validateDayOfMonth");
var isLeapYear = /* @__PURE__ */ __name((year) => {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}, "isLeapYear");
var parseDateValue = /* @__PURE__ */ __name((value, type, lower, upper) => {
  const dateVal = strictParseByte(stripLeadingZeroes(value));
  if (dateVal < lower || dateVal > upper) {
    throw new TypeError(`${type} must be between ${lower} and ${upper}, inclusive`);
  }
  return dateVal;
}, "parseDateValue");
var parseMilliseconds = /* @__PURE__ */ __name((value) => {
  if (value === null || value === void 0) {
    return 0;
  }
  return strictParseFloat32("0." + value) * 1e3;
}, "parseMilliseconds");
var parseOffsetToMilliseconds = /* @__PURE__ */ __name((value) => {
  const directionStr = value[0];
  let direction = 1;
  if (directionStr == "+") {
    direction = 1;
  } else if (directionStr == "-") {
    direction = -1;
  } else {
    throw new TypeError(`Offset direction, ${directionStr}, must be "+" or "-"`);
  }
  const hour = Number(value.substring(1, 3));
  const minute = Number(value.substring(4, 6));
  return direction * (hour * 60 + minute) * 60 * 1e3;
}, "parseOffsetToMilliseconds");
var stripLeadingZeroes = /* @__PURE__ */ __name((value) => {
  let idx = 0;
  while (idx < value.length - 1 && value.charAt(idx) === "0") {
    idx++;
  }
  if (idx === 0) {
    return value;
  }
  return value.slice(idx);
}, "stripLeadingZeroes");

// src/exceptions.ts
var _ServiceException = class _ServiceException extends Error {
  constructor(options) {
    super(options.message);
    Object.setPrototypeOf(this, _ServiceException.prototype);
    this.name = options.name;
    this.$fault = options.$fault;
    this.$metadata = options.$metadata;
  }
};
__name(_ServiceException, "ServiceException");
var ServiceException = _ServiceException;
var decorateServiceException = /* @__PURE__ */ __name((exception, additions = {}) => {
  Object.entries(additions).filter(([, v]) => v !== void 0).forEach(([k, v]) => {
    if (exception[k] == void 0 || exception[k] === "") {
      exception[k] = v;
    }
  });
  const message = exception.message || exception.Message || "UnknownError";
  exception.message = message;
  delete exception.Message;
  return exception;
}, "decorateServiceException");

// src/default-error-handler.ts
var throwDefaultError = /* @__PURE__ */ __name(({ output, parsedBody, exceptionCtor, errorCode }) => {
  const $metadata = deserializeMetadata(output);
  const statusCode = $metadata.httpStatusCode ? $metadata.httpStatusCode + "" : void 0;
  const response = new exceptionCtor({
    name: (parsedBody == null ? void 0 : parsedBody.code) || (parsedBody == null ? void 0 : parsedBody.Code) || errorCode || statusCode || "UnknownError",
    $fault: "client",
    $metadata
  });
  throw decorateServiceException(response, parsedBody);
}, "throwDefaultError");
var withBaseException = /* @__PURE__ */ __name((ExceptionCtor) => {
  return ({ output, parsedBody, errorCode }) => {
    throwDefaultError({ output, parsedBody, exceptionCtor: ExceptionCtor, errorCode });
  };
}, "withBaseException");
var deserializeMetadata = /* @__PURE__ */ __name((output) => ({
  httpStatusCode: output.statusCode,
  requestId: output.headers["x-amzn-requestid"] ?? output.headers["x-amzn-request-id"] ?? output.headers["x-amz-request-id"],
  extendedRequestId: output.headers["x-amz-id-2"],
  cfId: output.headers["x-amz-cf-id"]
}), "deserializeMetadata");

// src/defaults-mode.ts
var loadConfigsForDefaultMode = /* @__PURE__ */ __name((mode) => {
  switch (mode) {
    case "standard":
      return {
        retryMode: "standard",
        connectionTimeout: 3100
      };
    case "in-region":
      return {
        retryMode: "standard",
        connectionTimeout: 1100
      };
    case "cross-region":
      return {
        retryMode: "standard",
        connectionTimeout: 3100
      };
    case "mobile":
      return {
        retryMode: "standard",
        connectionTimeout: 3e4
      };
    default:
      return {};
  }
}, "loadConfigsForDefaultMode");

// src/emitWarningIfUnsupportedVersion.ts
var warningEmitted = false;
var emitWarningIfUnsupportedVersion = /* @__PURE__ */ __name((version) => {
  if (version && !warningEmitted && parseInt(version.substring(1, version.indexOf("."))) < 16) {
    warningEmitted = true;
  }
}, "emitWarningIfUnsupportedVersion");

// src/extensions/checksum.ts

var getChecksumConfiguration = /* @__PURE__ */ __name((runtimeConfig) => {
  const checksumAlgorithms = [];
  for (const id in import_types.AlgorithmId) {
    const algorithmId = import_types.AlgorithmId[id];
    if (runtimeConfig[algorithmId] === void 0) {
      continue;
    }
    checksumAlgorithms.push({
      algorithmId: () => algorithmId,
      checksumConstructor: () => runtimeConfig[algorithmId]
    });
  }
  return {
    _checksumAlgorithms: checksumAlgorithms,
    addChecksumAlgorithm(algo) {
      this._checksumAlgorithms.push(algo);
    },
    checksumAlgorithms() {
      return this._checksumAlgorithms;
    }
  };
}, "getChecksumConfiguration");
var resolveChecksumRuntimeConfig = /* @__PURE__ */ __name((clientConfig) => {
  const runtimeConfig = {};
  clientConfig.checksumAlgorithms().forEach((checksumAlgorithm) => {
    runtimeConfig[checksumAlgorithm.algorithmId()] = checksumAlgorithm.checksumConstructor();
  });
  return runtimeConfig;
}, "resolveChecksumRuntimeConfig");

// src/extensions/retry.ts
var getRetryConfiguration = /* @__PURE__ */ __name((runtimeConfig) => {
  let _retryStrategy = runtimeConfig.retryStrategy;
  return {
    setRetryStrategy(retryStrategy) {
      _retryStrategy = retryStrategy;
    },
    retryStrategy() {
      return _retryStrategy;
    }
  };
}, "getRetryConfiguration");
var resolveRetryRuntimeConfig = /* @__PURE__ */ __name((retryStrategyConfiguration) => {
  const runtimeConfig = {};
  runtimeConfig.retryStrategy = retryStrategyConfiguration.retryStrategy();
  return runtimeConfig;
}, "resolveRetryRuntimeConfig");

// src/extensions/defaultExtensionConfiguration.ts
var getDefaultExtensionConfiguration = /* @__PURE__ */ __name((runtimeConfig) => {
  return {
    ...getChecksumConfiguration(runtimeConfig),
    ...getRetryConfiguration(runtimeConfig)
  };
}, "getDefaultExtensionConfiguration");
var getDefaultClientConfiguration = getDefaultExtensionConfiguration;
var resolveDefaultRuntimeConfig = /* @__PURE__ */ __name((config) => {
  return {
    ...resolveChecksumRuntimeConfig(config),
    ...resolveRetryRuntimeConfig(config)
  };
}, "resolveDefaultRuntimeConfig");

// src/extended-encode-uri-component.ts
function extendedEncodeURIComponent(str) {
  return encodeURIComponent(str).replace(/[!'()*]/g, function(c) {
    return "%" + c.charCodeAt(0).toString(16).toUpperCase();
  });
}
__name(extendedEncodeURIComponent, "extendedEncodeURIComponent");

// src/get-array-if-single-item.ts
var getArrayIfSingleItem = /* @__PURE__ */ __name((mayBeArray) => Array.isArray(mayBeArray) ? mayBeArray : [mayBeArray], "getArrayIfSingleItem");

// src/get-value-from-text-node.ts
var getValueFromTextNode = /* @__PURE__ */ __name((obj) => {
  const textNodeName = "#text";
  for (const key in obj) {
    if (obj.hasOwnProperty(key) && obj[key][textNodeName] !== void 0) {
      obj[key] = obj[key][textNodeName];
    } else if (typeof obj[key] === "object" && obj[key] !== null) {
      obj[key] = getValueFromTextNode(obj[key]);
    }
  }
  return obj;
}, "getValueFromTextNode");

// src/lazy-json.ts
var StringWrapper = /* @__PURE__ */ __name(function() {
  const Class = Object.getPrototypeOf(this).constructor;
  const Constructor = Function.bind.apply(String, [null, ...arguments]);
  const instance = new Constructor();
  Object.setPrototypeOf(instance, Class.prototype);
  return instance;
}, "StringWrapper");
StringWrapper.prototype = Object.create(String.prototype, {
  constructor: {
    value: StringWrapper,
    enumerable: false,
    writable: true,
    configurable: true
  }
});
Object.setPrototypeOf(StringWrapper, String);
var _LazyJsonString = class _LazyJsonString extends StringWrapper {
  deserializeJSON() {
    return JSON.parse(super.toString());
  }
  toJSON() {
    return super.toString();
  }
  static fromObject(object) {
    if (object instanceof _LazyJsonString) {
      return object;
    } else if (object instanceof String || typeof object === "string") {
      return new _LazyJsonString(object);
    }
    return new _LazyJsonString(JSON.stringify(object));
  }
};
__name(_LazyJsonString, "LazyJsonString");
var LazyJsonString = _LazyJsonString;

// src/object-mapping.ts
function map(arg0, arg1, arg2) {
  let target;
  let filter;
  let instructions;
  if (typeof arg1 === "undefined" && typeof arg2 === "undefined") {
    target = {};
    instructions = arg0;
  } else {
    target = arg0;
    if (typeof arg1 === "function") {
      filter = arg1;
      instructions = arg2;
      return mapWithFilter(target, filter, instructions);
    } else {
      instructions = arg1;
    }
  }
  for (const key of Object.keys(instructions)) {
    if (!Array.isArray(instructions[key])) {
      target[key] = instructions[key];
      continue;
    }
    applyInstruction(target, null, instructions, key);
  }
  return target;
}
__name(map, "map");
var convertMap = /* @__PURE__ */ __name((target) => {
  const output = {};
  for (const [k, v] of Object.entries(target || {})) {
    output[k] = [, v];
  }
  return output;
}, "convertMap");
var take = /* @__PURE__ */ __name((source, instructions) => {
  const out = {};
  for (const key in instructions) {
    applyInstruction(out, source, instructions, key);
  }
  return out;
}, "take");
var mapWithFilter = /* @__PURE__ */ __name((target, filter, instructions) => {
  return map(
    target,
    Object.entries(instructions).reduce(
      (_instructions, [key, value]) => {
        if (Array.isArray(value)) {
          _instructions[key] = value;
        } else {
          if (typeof value === "function") {
            _instructions[key] = [filter, value()];
          } else {
            _instructions[key] = [filter, value];
          }
        }
        return _instructions;
      },
      {}
    )
  );
}, "mapWithFilter");
var applyInstruction = /* @__PURE__ */ __name((target, source, instructions, targetKey) => {
  if (source !== null) {
    let instruction = instructions[targetKey];
    if (typeof instruction === "function") {
      instruction = [, instruction];
    }
    const [filter2 = nonNullish, valueFn = pass, sourceKey = targetKey] = instruction;
    if (typeof filter2 === "function" && filter2(source[sourceKey]) || typeof filter2 !== "function" && !!filter2) {
      target[targetKey] = valueFn(source[sourceKey]);
    }
    return;
  }
  let [filter, value] = instructions[targetKey];
  if (typeof value === "function") {
    let _value;
    const defaultFilterPassed = filter === void 0 && (_value = value()) != null;
    const customFilterPassed = typeof filter === "function" && !!filter(void 0) || typeof filter !== "function" && !!filter;
    if (defaultFilterPassed) {
      target[targetKey] = _value;
    } else if (customFilterPassed) {
      target[targetKey] = value();
    }
  } else {
    const defaultFilterPassed = filter === void 0 && value != null;
    const customFilterPassed = typeof filter === "function" && !!filter(value) || typeof filter !== "function" && !!filter;
    if (defaultFilterPassed || customFilterPassed) {
      target[targetKey] = value;
    }
  }
}, "applyInstruction");
var nonNullish = /* @__PURE__ */ __name((_) => _ != null, "nonNullish");
var pass = /* @__PURE__ */ __name((_) => _, "pass");

// src/resolve-path.ts
var resolvedPath = /* @__PURE__ */ __name((resolvedPath2, input, memberName, labelValueProvider, uriLabel, isGreedyLabel) => {
  if (input != null && input[memberName] !== void 0) {
    const labelValue = labelValueProvider();
    if (labelValue.length <= 0) {
      throw new Error("Empty value provided for input HTTP label: " + memberName + ".");
    }
    resolvedPath2 = resolvedPath2.replace(
      uriLabel,
      isGreedyLabel ? labelValue.split("/").map((segment) => extendedEncodeURIComponent(segment)).join("/") : extendedEncodeURIComponent(labelValue)
    );
  } else {
    throw new Error("No value provided for input HTTP label: " + memberName + ".");
  }
  return resolvedPath2;
}, "resolvedPath");

// src/ser-utils.ts
var serializeFloat = /* @__PURE__ */ __name((value) => {
  if (value !== value) {
    return "NaN";
  }
  switch (value) {
    case Infinity:
      return "Infinity";
    case -Infinity:
      return "-Infinity";
    default:
      return value;
  }
}, "serializeFloat");
var serializeDateTime = /* @__PURE__ */ __name((date) => date.toISOString().replace(".000Z", "Z"), "serializeDateTime");

// src/serde-json.ts
var _json = /* @__PURE__ */ __name((obj) => {
  if (obj == null) {
    return {};
  }
  if (Array.isArray(obj)) {
    return obj.filter((_) => _ != null).map(_json);
  }
  if (typeof obj === "object") {
    const target = {};
    for (const key of Object.keys(obj)) {
      if (obj[key] == null) {
        continue;
      }
      target[key] = _json(obj[key]);
    }
    return target;
  }
  return obj;
}, "_json");

// src/split-every.ts
function splitEvery(value, delimiter, numDelimiters) {
  if (numDelimiters <= 0 || !Number.isInteger(numDelimiters)) {
    throw new Error("Invalid number of delimiters (" + numDelimiters + ") for splitEvery.");
  }
  const segments = value.split(delimiter);
  if (numDelimiters === 1) {
    return segments;
  }
  const compoundSegments = [];
  let currentSegment = "";
  for (let i = 0; i < segments.length; i++) {
    if (currentSegment === "") {
      currentSegment = segments[i];
    } else {
      currentSegment += delimiter + segments[i];
    }
    if ((i + 1) % numDelimiters === 0) {
      compoundSegments.push(currentSegment);
      currentSegment = "";
    }
  }
  if (currentSegment !== "") {
    compoundSegments.push(currentSegment);
  }
  return compoundSegments;
}
__name(splitEvery, "splitEvery");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 5756:
/***/ ((module) => {

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  AlgorithmId: () => AlgorithmId,
  EndpointURLScheme: () => EndpointURLScheme,
  FieldPosition: () => FieldPosition,
  HttpApiKeyAuthLocation: () => HttpApiKeyAuthLocation,
  HttpAuthLocation: () => HttpAuthLocation,
  IniSectionType: () => IniSectionType,
  RequestHandlerProtocol: () => RequestHandlerProtocol,
  SMITHY_CONTEXT_KEY: () => SMITHY_CONTEXT_KEY,
  getDefaultClientConfiguration: () => getDefaultClientConfiguration,
  resolveDefaultRuntimeConfig: () => resolveDefaultRuntimeConfig
});
module.exports = __toCommonJS(src_exports);

// src/auth/auth.ts
var HttpAuthLocation = /* @__PURE__ */ ((HttpAuthLocation2) => {
  HttpAuthLocation2["HEADER"] = "header";
  HttpAuthLocation2["QUERY"] = "query";
  return HttpAuthLocation2;
})(HttpAuthLocation || {});

// src/auth/HttpApiKeyAuth.ts
var HttpApiKeyAuthLocation = /* @__PURE__ */ ((HttpApiKeyAuthLocation2) => {
  HttpApiKeyAuthLocation2["HEADER"] = "header";
  HttpApiKeyAuthLocation2["QUERY"] = "query";
  return HttpApiKeyAuthLocation2;
})(HttpApiKeyAuthLocation || {});

// src/endpoint.ts
var EndpointURLScheme = /* @__PURE__ */ ((EndpointURLScheme2) => {
  EndpointURLScheme2["HTTP"] = "http";
  EndpointURLScheme2["HTTPS"] = "https";
  return EndpointURLScheme2;
})(EndpointURLScheme || {});

// src/extensions/checksum.ts
var AlgorithmId = /* @__PURE__ */ ((AlgorithmId2) => {
  AlgorithmId2["MD5"] = "md5";
  AlgorithmId2["CRC32"] = "crc32";
  AlgorithmId2["CRC32C"] = "crc32c";
  AlgorithmId2["SHA1"] = "sha1";
  AlgorithmId2["SHA256"] = "sha256";
  return AlgorithmId2;
})(AlgorithmId || {});
var getChecksumConfiguration = /* @__PURE__ */ __name((runtimeConfig) => {
  const checksumAlgorithms = [];
  if (runtimeConfig.sha256 !== void 0) {
    checksumAlgorithms.push({
      algorithmId: () => "sha256" /* SHA256 */,
      checksumConstructor: () => runtimeConfig.sha256
    });
  }
  if (runtimeConfig.md5 != void 0) {
    checksumAlgorithms.push({
      algorithmId: () => "md5" /* MD5 */,
      checksumConstructor: () => runtimeConfig.md5
    });
  }
  return {
    _checksumAlgorithms: checksumAlgorithms,
    addChecksumAlgorithm(algo) {
      this._checksumAlgorithms.push(algo);
    },
    checksumAlgorithms() {
      return this._checksumAlgorithms;
    }
  };
}, "getChecksumConfiguration");
var resolveChecksumRuntimeConfig = /* @__PURE__ */ __name((clientConfig) => {
  const runtimeConfig = {};
  clientConfig.checksumAlgorithms().forEach((checksumAlgorithm) => {
    runtimeConfig[checksumAlgorithm.algorithmId()] = checksumAlgorithm.checksumConstructor();
  });
  return runtimeConfig;
}, "resolveChecksumRuntimeConfig");

// src/extensions/defaultClientConfiguration.ts
var getDefaultClientConfiguration = /* @__PURE__ */ __name((runtimeConfig) => {
  return {
    ...getChecksumConfiguration(runtimeConfig)
  };
}, "getDefaultClientConfiguration");
var resolveDefaultRuntimeConfig = /* @__PURE__ */ __name((config) => {
  return {
    ...resolveChecksumRuntimeConfig(config)
  };
}, "resolveDefaultRuntimeConfig");

// src/http.ts
var FieldPosition = /* @__PURE__ */ ((FieldPosition2) => {
  FieldPosition2[FieldPosition2["HEADER"] = 0] = "HEADER";
  FieldPosition2[FieldPosition2["TRAILER"] = 1] = "TRAILER";
  return FieldPosition2;
})(FieldPosition || {});

// src/middleware.ts
var SMITHY_CONTEXT_KEY = "__smithy_context";

// src/profile.ts
var IniSectionType = /* @__PURE__ */ ((IniSectionType2) => {
  IniSectionType2["PROFILE"] = "profile";
  IniSectionType2["SSO_SESSION"] = "sso-session";
  IniSectionType2["SERVICES"] = "services";
  return IniSectionType2;
})(IniSectionType || {});

// src/transfer.ts
var RequestHandlerProtocol = /* @__PURE__ */ ((RequestHandlerProtocol2) => {
  RequestHandlerProtocol2["HTTP_0_9"] = "http/0.9";
  RequestHandlerProtocol2["HTTP_1_0"] = "http/1.0";
  RequestHandlerProtocol2["TDS_8_0"] = "tds/8.0";
  return RequestHandlerProtocol2;
})(RequestHandlerProtocol || {});
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 4681:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  parseUrl: () => parseUrl
});
module.exports = __toCommonJS(src_exports);
var import_querystring_parser = __nccwpck_require__(4769);
var parseUrl = /* @__PURE__ */ __name((url) => {
  if (typeof url === "string") {
    return parseUrl(new URL(url));
  }
  const { hostname, pathname, port, protocol, search } = url;
  let query;
  if (search) {
    query = (0, import_querystring_parser.parseQueryString)(search);
  }
  return {
    hostname,
    port: port ? parseInt(port) : void 0,
    protocol,
    path: pathname,
    query
  };
}, "parseUrl");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 305:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.fromBase64 = void 0;
const util_buffer_from_1 = __nccwpck_require__(1381);
const BASE64_REGEX = /^[A-Za-z0-9+/]*={0,2}$/;
const fromBase64 = (input) => {
    if ((input.length * 3) % 4 !== 0) {
        throw new TypeError(`Incorrect padding on base64 string.`);
    }
    if (!BASE64_REGEX.exec(input)) {
        throw new TypeError(`Invalid base64 string.`);
    }
    const buffer = (0, util_buffer_from_1.fromString)(input, "base64");
    return new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
};
exports.fromBase64 = fromBase64;


/***/ }),

/***/ 5600:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __reExport = (target, mod, secondTarget) => (__copyProps(target, mod, "default"), secondTarget && __copyProps(secondTarget, mod, "default"));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
module.exports = __toCommonJS(src_exports);
__reExport(src_exports, __nccwpck_require__(305), module.exports);
__reExport(src_exports, __nccwpck_require__(4730), module.exports);
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 4730:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.toBase64 = void 0;
const util_buffer_from_1 = __nccwpck_require__(1381);
const util_utf8_1 = __nccwpck_require__(1895);
const toBase64 = (_input) => {
    let input;
    if (typeof _input === "string") {
        input = (0, util_utf8_1.fromUtf8)(_input);
    }
    else {
        input = _input;
    }
    if (typeof input !== "object" || typeof input.byteOffset !== "number" || typeof input.byteLength !== "number") {
        throw new Error("@smithy/util-base64: toBase64 encoder function only accepts string | Uint8Array.");
    }
    return (0, util_buffer_from_1.fromArrayBuffer)(input.buffer, input.byteOffset, input.byteLength).toString("base64");
};
exports.toBase64 = toBase64;


/***/ }),

/***/ 8075:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  calculateBodyLength: () => calculateBodyLength
});
module.exports = __toCommonJS(src_exports);

// src/calculateBodyLength.ts
var import_fs = __nccwpck_require__(7147);
var calculateBodyLength = /* @__PURE__ */ __name((body) => {
  if (!body) {
    return 0;
  }
  if (typeof body === "string") {
    return Buffer.byteLength(body);
  } else if (typeof body.byteLength === "number") {
    return body.byteLength;
  } else if (typeof body.size === "number") {
    return body.size;
  } else if (typeof body.start === "number" && typeof body.end === "number") {
    return body.end + 1 - body.start;
  } else if (typeof body.path === "string" || Buffer.isBuffer(body.path)) {
    return (0, import_fs.lstatSync)(body.path).size;
  } else if (typeof body.fd === "number") {
    return (0, import_fs.fstatSync)(body.fd).size;
  }
  throw new Error(`Body Length computation failed for ${body}`);
}, "calculateBodyLength");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 1381:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  fromArrayBuffer: () => fromArrayBuffer,
  fromString: () => fromString
});
module.exports = __toCommonJS(src_exports);
var import_is_array_buffer = __nccwpck_require__(780);
var import_buffer = __nccwpck_require__(4300);
var fromArrayBuffer = /* @__PURE__ */ __name((input, offset = 0, length = input.byteLength - offset) => {
  if (!(0, import_is_array_buffer.isArrayBuffer)(input)) {
    throw new TypeError(`The "input" argument must be ArrayBuffer. Received type ${typeof input} (${input})`);
  }
  return import_buffer.Buffer.from(input, offset, length);
}, "fromArrayBuffer");
var fromString = /* @__PURE__ */ __name((input, encoding) => {
  if (typeof input !== "string") {
    throw new TypeError(`The "input" argument must be of type string. Received type ${typeof input} (${input})`);
  }
  return encoding ? import_buffer.Buffer.from(input, encoding) : import_buffer.Buffer.from(input);
}, "fromString");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 3375:
/***/ ((module) => {

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  SelectorType: () => SelectorType,
  booleanSelector: () => booleanSelector,
  numberSelector: () => numberSelector
});
module.exports = __toCommonJS(src_exports);

// src/booleanSelector.ts
var booleanSelector = /* @__PURE__ */ __name((obj, key, type) => {
  if (!(key in obj))
    return void 0;
  if (obj[key] === "true")
    return true;
  if (obj[key] === "false")
    return false;
  throw new Error(`Cannot load ${type} "${key}". Expected "true" or "false", got ${obj[key]}.`);
}, "booleanSelector");

// src/numberSelector.ts
var numberSelector = /* @__PURE__ */ __name((obj, key, type) => {
  if (!(key in obj))
    return void 0;
  const numberValue = parseInt(obj[key], 10);
  if (Number.isNaN(numberValue)) {
    throw new TypeError(`Cannot load ${type} '${key}'. Expected number, got '${obj[key]}'.`);
  }
  return numberValue;
}, "numberSelector");

// src/types.ts
var SelectorType = /* @__PURE__ */ ((SelectorType2) => {
  SelectorType2["ENV"] = "env";
  SelectorType2["CONFIG"] = "shared config entry";
  return SelectorType2;
})(SelectorType || {});
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 2429:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  resolveDefaultsModeConfig: () => resolveDefaultsModeConfig
});
module.exports = __toCommonJS(src_exports);

// src/resolveDefaultsModeConfig.ts
var import_config_resolver = __nccwpck_require__(3098);
var import_node_config_provider = __nccwpck_require__(3461);
var import_property_provider = __nccwpck_require__(9721);

// src/constants.ts
var AWS_EXECUTION_ENV = "AWS_EXECUTION_ENV";
var AWS_REGION_ENV = "AWS_REGION";
var AWS_DEFAULT_REGION_ENV = "AWS_DEFAULT_REGION";
var ENV_IMDS_DISABLED = "AWS_EC2_METADATA_DISABLED";
var DEFAULTS_MODE_OPTIONS = ["in-region", "cross-region", "mobile", "standard", "legacy"];
var IMDS_REGION_PATH = "/latest/meta-data/placement/region";

// src/defaultsModeConfig.ts
var AWS_DEFAULTS_MODE_ENV = "AWS_DEFAULTS_MODE";
var AWS_DEFAULTS_MODE_CONFIG = "defaults_mode";
var NODE_DEFAULTS_MODE_CONFIG_OPTIONS = {
  environmentVariableSelector: (env) => {
    return env[AWS_DEFAULTS_MODE_ENV];
  },
  configFileSelector: (profile) => {
    return profile[AWS_DEFAULTS_MODE_CONFIG];
  },
  default: "legacy"
};

// src/resolveDefaultsModeConfig.ts
var resolveDefaultsModeConfig = /* @__PURE__ */ __name(({
  region = (0, import_node_config_provider.loadConfig)(import_config_resolver.NODE_REGION_CONFIG_OPTIONS),
  defaultsMode = (0, import_node_config_provider.loadConfig)(NODE_DEFAULTS_MODE_CONFIG_OPTIONS)
} = {}) => (0, import_property_provider.memoize)(async () => {
  const mode = typeof defaultsMode === "function" ? await defaultsMode() : defaultsMode;
  switch (mode == null ? void 0 : mode.toLowerCase()) {
    case "auto":
      return resolveNodeDefaultsModeAuto(region);
    case "in-region":
    case "cross-region":
    case "mobile":
    case "standard":
    case "legacy":
      return Promise.resolve(mode == null ? void 0 : mode.toLocaleLowerCase());
    case void 0:
      return Promise.resolve("legacy");
    default:
      throw new Error(
        `Invalid parameter for "defaultsMode", expect ${DEFAULTS_MODE_OPTIONS.join(", ")}, got ${mode}`
      );
  }
}), "resolveDefaultsModeConfig");
var resolveNodeDefaultsModeAuto = /* @__PURE__ */ __name(async (clientRegion) => {
  if (clientRegion) {
    const resolvedRegion = typeof clientRegion === "function" ? await clientRegion() : clientRegion;
    const inferredRegion = await inferPhysicalRegion();
    if (!inferredRegion) {
      return "standard";
    }
    if (resolvedRegion === inferredRegion) {
      return "in-region";
    } else {
      return "cross-region";
    }
  }
  return "standard";
}, "resolveNodeDefaultsModeAuto");
var inferPhysicalRegion = /* @__PURE__ */ __name(async () => {
  if (process.env[AWS_EXECUTION_ENV] && (process.env[AWS_REGION_ENV] || process.env[AWS_DEFAULT_REGION_ENV])) {
    return process.env[AWS_REGION_ENV] ?? process.env[AWS_DEFAULT_REGION_ENV];
  }
  if (!process.env[ENV_IMDS_DISABLED]) {
    try {
      const { getInstanceMetadataEndpoint, httpRequest } = await Promise.resolve().then(() => __toESM(__nccwpck_require__(7477)));
      const endpoint = await getInstanceMetadataEndpoint();
      return (await httpRequest({ ...endpoint, path: IMDS_REGION_PATH })).toString();
    } catch (e) {
    }
  }
}, "inferPhysicalRegion");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 5473:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  EndpointError: () => EndpointError,
  customEndpointFunctions: () => customEndpointFunctions,
  isIpAddress: () => isIpAddress,
  isValidHostLabel: () => isValidHostLabel,
  resolveEndpoint: () => resolveEndpoint
});
module.exports = __toCommonJS(src_exports);

// src/lib/isIpAddress.ts
var IP_V4_REGEX = new RegExp(
  `^(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]\\d|\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]\\d|\\d)){3}$`
);
var isIpAddress = /* @__PURE__ */ __name((value) => IP_V4_REGEX.test(value) || value.startsWith("[") && value.endsWith("]"), "isIpAddress");

// src/lib/isValidHostLabel.ts
var VALID_HOST_LABEL_REGEX = new RegExp(`^(?!.*-$)(?!-)[a-zA-Z0-9-]{1,63}$`);
var isValidHostLabel = /* @__PURE__ */ __name((value, allowSubDomains = false) => {
  if (!allowSubDomains) {
    return VALID_HOST_LABEL_REGEX.test(value);
  }
  const labels = value.split(".");
  for (const label of labels) {
    if (!isValidHostLabel(label)) {
      return false;
    }
  }
  return true;
}, "isValidHostLabel");

// src/utils/customEndpointFunctions.ts
var customEndpointFunctions = {};

// src/debug/debugId.ts
var debugId = "endpoints";

// src/debug/toDebugString.ts
function toDebugString(input) {
  if (typeof input !== "object" || input == null) {
    return input;
  }
  if ("ref" in input) {
    return `$${toDebugString(input.ref)}`;
  }
  if ("fn" in input) {
    return `${input.fn}(${(input.argv || []).map(toDebugString).join(", ")})`;
  }
  return JSON.stringify(input, null, 2);
}
__name(toDebugString, "toDebugString");

// src/types/EndpointError.ts
var _EndpointError = class _EndpointError extends Error {
  constructor(message) {
    super(message);
    this.name = "EndpointError";
  }
};
__name(_EndpointError, "EndpointError");
var EndpointError = _EndpointError;

// src/lib/booleanEquals.ts
var booleanEquals = /* @__PURE__ */ __name((value1, value2) => value1 === value2, "booleanEquals");

// src/lib/getAttrPathList.ts
var getAttrPathList = /* @__PURE__ */ __name((path) => {
  const parts = path.split(".");
  const pathList = [];
  for (const part of parts) {
    const squareBracketIndex = part.indexOf("[");
    if (squareBracketIndex !== -1) {
      if (part.indexOf("]") !== part.length - 1) {
        throw new EndpointError(`Path: '${path}' does not end with ']'`);
      }
      const arrayIndex = part.slice(squareBracketIndex + 1, -1);
      if (Number.isNaN(parseInt(arrayIndex))) {
        throw new EndpointError(`Invalid array index: '${arrayIndex}' in path: '${path}'`);
      }
      if (squareBracketIndex !== 0) {
        pathList.push(part.slice(0, squareBracketIndex));
      }
      pathList.push(arrayIndex);
    } else {
      pathList.push(part);
    }
  }
  return pathList;
}, "getAttrPathList");

// src/lib/getAttr.ts
var getAttr = /* @__PURE__ */ __name((value, path) => getAttrPathList(path).reduce((acc, index) => {
  if (typeof acc !== "object") {
    throw new EndpointError(`Index '${index}' in '${path}' not found in '${JSON.stringify(value)}'`);
  } else if (Array.isArray(acc)) {
    return acc[parseInt(index)];
  }
  return acc[index];
}, value), "getAttr");

// src/lib/isSet.ts
var isSet = /* @__PURE__ */ __name((value) => value != null, "isSet");

// src/lib/not.ts
var not = /* @__PURE__ */ __name((value) => !value, "not");

// src/lib/parseURL.ts
var import_types3 = __nccwpck_require__(5756);
var DEFAULT_PORTS = {
  [import_types3.EndpointURLScheme.HTTP]: 80,
  [import_types3.EndpointURLScheme.HTTPS]: 443
};
var parseURL = /* @__PURE__ */ __name((value) => {
  const whatwgURL = (() => {
    try {
      if (value instanceof URL) {
        return value;
      }
      if (typeof value === "object" && "hostname" in value) {
        const { hostname: hostname2, port, protocol: protocol2 = "", path = "", query = {} } = value;
        const url = new URL(`${protocol2}//${hostname2}${port ? `:${port}` : ""}${path}`);
        url.search = Object.entries(query).map(([k, v]) => `${k}=${v}`).join("&");
        return url;
      }
      return new URL(value);
    } catch (error) {
      return null;
    }
  })();
  if (!whatwgURL) {
    console.error(`Unable to parse ${JSON.stringify(value)} as a whatwg URL.`);
    return null;
  }
  const urlString = whatwgURL.href;
  const { host, hostname, pathname, protocol, search } = whatwgURL;
  if (search) {
    return null;
  }
  const scheme = protocol.slice(0, -1);
  if (!Object.values(import_types3.EndpointURLScheme).includes(scheme)) {
    return null;
  }
  const isIp = isIpAddress(hostname);
  const inputContainsDefaultPort = urlString.includes(`${host}:${DEFAULT_PORTS[scheme]}`) || typeof value === "string" && value.includes(`${host}:${DEFAULT_PORTS[scheme]}`);
  const authority = `${host}${inputContainsDefaultPort ? `:${DEFAULT_PORTS[scheme]}` : ``}`;
  return {
    scheme,
    authority,
    path: pathname,
    normalizedPath: pathname.endsWith("/") ? pathname : `${pathname}/`,
    isIp
  };
}, "parseURL");

// src/lib/stringEquals.ts
var stringEquals = /* @__PURE__ */ __name((value1, value2) => value1 === value2, "stringEquals");

// src/lib/substring.ts
var substring = /* @__PURE__ */ __name((input, start, stop, reverse) => {
  if (start >= stop || input.length < stop) {
    return null;
  }
  if (!reverse) {
    return input.substring(start, stop);
  }
  return input.substring(input.length - stop, input.length - start);
}, "substring");

// src/lib/uriEncode.ts
var uriEncode = /* @__PURE__ */ __name((value) => encodeURIComponent(value).replace(/[!*'()]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`), "uriEncode");

// src/utils/endpointFunctions.ts
var endpointFunctions = {
  booleanEquals,
  getAttr,
  isSet,
  isValidHostLabel,
  not,
  parseURL,
  stringEquals,
  substring,
  uriEncode
};

// src/utils/evaluateTemplate.ts
var evaluateTemplate = /* @__PURE__ */ __name((template, options) => {
  const evaluatedTemplateArr = [];
  const templateContext = {
    ...options.endpointParams,
    ...options.referenceRecord
  };
  let currentIndex = 0;
  while (currentIndex < template.length) {
    const openingBraceIndex = template.indexOf("{", currentIndex);
    if (openingBraceIndex === -1) {
      evaluatedTemplateArr.push(template.slice(currentIndex));
      break;
    }
    evaluatedTemplateArr.push(template.slice(currentIndex, openingBraceIndex));
    const closingBraceIndex = template.indexOf("}", openingBraceIndex);
    if (closingBraceIndex === -1) {
      evaluatedTemplateArr.push(template.slice(openingBraceIndex));
      break;
    }
    if (template[openingBraceIndex + 1] === "{" && template[closingBraceIndex + 1] === "}") {
      evaluatedTemplateArr.push(template.slice(openingBraceIndex + 1, closingBraceIndex));
      currentIndex = closingBraceIndex + 2;
    }
    const parameterName = template.substring(openingBraceIndex + 1, closingBraceIndex);
    if (parameterName.includes("#")) {
      const [refName, attrName] = parameterName.split("#");
      evaluatedTemplateArr.push(getAttr(templateContext[refName], attrName));
    } else {
      evaluatedTemplateArr.push(templateContext[parameterName]);
    }
    currentIndex = closingBraceIndex + 1;
  }
  return evaluatedTemplateArr.join("");
}, "evaluateTemplate");

// src/utils/getReferenceValue.ts
var getReferenceValue = /* @__PURE__ */ __name(({ ref }, options) => {
  const referenceRecord = {
    ...options.endpointParams,
    ...options.referenceRecord
  };
  return referenceRecord[ref];
}, "getReferenceValue");

// src/utils/evaluateExpression.ts
var evaluateExpression = /* @__PURE__ */ __name((obj, keyName, options) => {
  if (typeof obj === "string") {
    return evaluateTemplate(obj, options);
  } else if (obj["fn"]) {
    return callFunction(obj, options);
  } else if (obj["ref"]) {
    return getReferenceValue(obj, options);
  }
  throw new EndpointError(`'${keyName}': ${String(obj)} is not a string, function or reference.`);
}, "evaluateExpression");

// src/utils/callFunction.ts
var callFunction = /* @__PURE__ */ __name(({ fn, argv }, options) => {
  const evaluatedArgs = argv.map(
    (arg) => ["boolean", "number"].includes(typeof arg) ? arg : evaluateExpression(arg, "arg", options)
  );
  const fnSegments = fn.split(".");
  if (fnSegments[0] in customEndpointFunctions && fnSegments[1] != null) {
    return customEndpointFunctions[fnSegments[0]][fnSegments[1]](...evaluatedArgs);
  }
  return endpointFunctions[fn](...evaluatedArgs);
}, "callFunction");

// src/utils/evaluateCondition.ts
var evaluateCondition = /* @__PURE__ */ __name(({ assign, ...fnArgs }, options) => {
  var _a, _b;
  if (assign && assign in options.referenceRecord) {
    throw new EndpointError(`'${assign}' is already defined in Reference Record.`);
  }
  const value = callFunction(fnArgs, options);
  (_b = (_a = options.logger) == null ? void 0 : _a.debug) == null ? void 0 : _b.call(_a, `${debugId} evaluateCondition: ${toDebugString(fnArgs)} = ${toDebugString(value)}`);
  return {
    result: value === "" ? true : !!value,
    ...assign != null && { toAssign: { name: assign, value } }
  };
}, "evaluateCondition");

// src/utils/evaluateConditions.ts
var evaluateConditions = /* @__PURE__ */ __name((conditions = [], options) => {
  var _a, _b;
  const conditionsReferenceRecord = {};
  for (const condition of conditions) {
    const { result, toAssign } = evaluateCondition(condition, {
      ...options,
      referenceRecord: {
        ...options.referenceRecord,
        ...conditionsReferenceRecord
      }
    });
    if (!result) {
      return { result };
    }
    if (toAssign) {
      conditionsReferenceRecord[toAssign.name] = toAssign.value;
      (_b = (_a = options.logger) == null ? void 0 : _a.debug) == null ? void 0 : _b.call(_a, `${debugId} assign: ${toAssign.name} := ${toDebugString(toAssign.value)}`);
    }
  }
  return { result: true, referenceRecord: conditionsReferenceRecord };
}, "evaluateConditions");

// src/utils/getEndpointHeaders.ts
var getEndpointHeaders = /* @__PURE__ */ __name((headers, options) => Object.entries(headers).reduce(
  (acc, [headerKey, headerVal]) => ({
    ...acc,
    [headerKey]: headerVal.map((headerValEntry) => {
      const processedExpr = evaluateExpression(headerValEntry, "Header value entry", options);
      if (typeof processedExpr !== "string") {
        throw new EndpointError(`Header '${headerKey}' value '${processedExpr}' is not a string`);
      }
      return processedExpr;
    })
  }),
  {}
), "getEndpointHeaders");

// src/utils/getEndpointProperty.ts
var getEndpointProperty = /* @__PURE__ */ __name((property, options) => {
  if (Array.isArray(property)) {
    return property.map((propertyEntry) => getEndpointProperty(propertyEntry, options));
  }
  switch (typeof property) {
    case "string":
      return evaluateTemplate(property, options);
    case "object":
      if (property === null) {
        throw new EndpointError(`Unexpected endpoint property: ${property}`);
      }
      return getEndpointProperties(property, options);
    case "boolean":
      return property;
    default:
      throw new EndpointError(`Unexpected endpoint property type: ${typeof property}`);
  }
}, "getEndpointProperty");

// src/utils/getEndpointProperties.ts
var getEndpointProperties = /* @__PURE__ */ __name((properties, options) => Object.entries(properties).reduce(
  (acc, [propertyKey, propertyVal]) => ({
    ...acc,
    [propertyKey]: getEndpointProperty(propertyVal, options)
  }),
  {}
), "getEndpointProperties");

// src/utils/getEndpointUrl.ts
var getEndpointUrl = /* @__PURE__ */ __name((endpointUrl, options) => {
  const expression = evaluateExpression(endpointUrl, "Endpoint URL", options);
  if (typeof expression === "string") {
    try {
      return new URL(expression);
    } catch (error) {
      console.error(`Failed to construct URL with ${expression}`, error);
      throw error;
    }
  }
  throw new EndpointError(`Endpoint URL must be a string, got ${typeof expression}`);
}, "getEndpointUrl");

// src/utils/evaluateEndpointRule.ts
var evaluateEndpointRule = /* @__PURE__ */ __name((endpointRule, options) => {
  var _a, _b;
  const { conditions, endpoint } = endpointRule;
  const { result, referenceRecord } = evaluateConditions(conditions, options);
  if (!result) {
    return;
  }
  const endpointRuleOptions = {
    ...options,
    referenceRecord: { ...options.referenceRecord, ...referenceRecord }
  };
  const { url, properties, headers } = endpoint;
  (_b = (_a = options.logger) == null ? void 0 : _a.debug) == null ? void 0 : _b.call(_a, `${debugId} Resolving endpoint from template: ${toDebugString(endpoint)}`);
  return {
    ...headers != void 0 && {
      headers: getEndpointHeaders(headers, endpointRuleOptions)
    },
    ...properties != void 0 && {
      properties: getEndpointProperties(properties, endpointRuleOptions)
    },
    url: getEndpointUrl(url, endpointRuleOptions)
  };
}, "evaluateEndpointRule");

// src/utils/evaluateErrorRule.ts
var evaluateErrorRule = /* @__PURE__ */ __name((errorRule, options) => {
  const { conditions, error } = errorRule;
  const { result, referenceRecord } = evaluateConditions(conditions, options);
  if (!result) {
    return;
  }
  throw new EndpointError(
    evaluateExpression(error, "Error", {
      ...options,
      referenceRecord: { ...options.referenceRecord, ...referenceRecord }
    })
  );
}, "evaluateErrorRule");

// src/utils/evaluateTreeRule.ts
var evaluateTreeRule = /* @__PURE__ */ __name((treeRule, options) => {
  const { conditions, rules } = treeRule;
  const { result, referenceRecord } = evaluateConditions(conditions, options);
  if (!result) {
    return;
  }
  return evaluateRules(rules, {
    ...options,
    referenceRecord: { ...options.referenceRecord, ...referenceRecord }
  });
}, "evaluateTreeRule");

// src/utils/evaluateRules.ts
var evaluateRules = /* @__PURE__ */ __name((rules, options) => {
  for (const rule of rules) {
    if (rule.type === "endpoint") {
      const endpointOrUndefined = evaluateEndpointRule(rule, options);
      if (endpointOrUndefined) {
        return endpointOrUndefined;
      }
    } else if (rule.type === "error") {
      evaluateErrorRule(rule, options);
    } else if (rule.type === "tree") {
      const endpointOrUndefined = evaluateTreeRule(rule, options);
      if (endpointOrUndefined) {
        return endpointOrUndefined;
      }
    } else {
      throw new EndpointError(`Unknown endpoint rule: ${rule}`);
    }
  }
  throw new EndpointError(`Rules evaluation failed`);
}, "evaluateRules");

// src/resolveEndpoint.ts
var resolveEndpoint = /* @__PURE__ */ __name((ruleSetObject, options) => {
  var _a, _b, _c, _d, _e;
  const { endpointParams, logger } = options;
  const { parameters, rules } = ruleSetObject;
  (_b = (_a = options.logger) == null ? void 0 : _a.debug) == null ? void 0 : _b.call(_a, `${debugId} Initial EndpointParams: ${toDebugString(endpointParams)}`);
  const paramsWithDefault = Object.entries(parameters).filter(([, v]) => v.default != null).map(([k, v]) => [k, v.default]);
  if (paramsWithDefault.length > 0) {
    for (const [paramKey, paramDefaultValue] of paramsWithDefault) {
      endpointParams[paramKey] = endpointParams[paramKey] ?? paramDefaultValue;
    }
  }
  const requiredParams = Object.entries(parameters).filter(([, v]) => v.required).map(([k]) => k);
  for (const requiredParam of requiredParams) {
    if (endpointParams[requiredParam] == null) {
      throw new EndpointError(`Missing required parameter: '${requiredParam}'`);
    }
  }
  const endpoint = evaluateRules(rules, { endpointParams, logger, referenceRecord: {} });
  if ((_c = options.endpointParams) == null ? void 0 : _c.Endpoint) {
    try {
      const givenEndpoint = new URL(options.endpointParams.Endpoint);
      const { protocol, port } = givenEndpoint;
      endpoint.url.protocol = protocol;
      endpoint.url.port = port;
    } catch (e) {
    }
  }
  (_e = (_d = options.logger) == null ? void 0 : _d.debug) == null ? void 0 : _e.call(_d, `${debugId} Resolved endpoint: ${toDebugString(endpoint)}`);
  return endpoint;
}, "resolveEndpoint");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 5364:
/***/ ((module) => {

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  fromHex: () => fromHex,
  toHex: () => toHex
});
module.exports = __toCommonJS(src_exports);
var SHORT_TO_HEX = {};
var HEX_TO_SHORT = {};
for (let i = 0; i < 256; i++) {
  let encodedByte = i.toString(16).toLowerCase();
  if (encodedByte.length === 1) {
    encodedByte = `0${encodedByte}`;
  }
  SHORT_TO_HEX[i] = encodedByte;
  HEX_TO_SHORT[encodedByte] = i;
}
function fromHex(encoded) {
  if (encoded.length % 2 !== 0) {
    throw new Error("Hex encoded strings must have an even number length");
  }
  const out = new Uint8Array(encoded.length / 2);
  for (let i = 0; i < encoded.length; i += 2) {
    const encodedByte = encoded.slice(i, i + 2).toLowerCase();
    if (encodedByte in HEX_TO_SHORT) {
      out[i / 2] = HEX_TO_SHORT[encodedByte];
    } else {
      throw new Error(`Cannot decode unrecognized sequence ${encodedByte} as hexadecimal`);
    }
  }
  return out;
}
__name(fromHex, "fromHex");
function toHex(bytes) {
  let out = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    out += SHORT_TO_HEX[bytes[i]];
  }
  return out;
}
__name(toHex, "toHex");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 2390:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  getSmithyContext: () => getSmithyContext,
  normalizeProvider: () => normalizeProvider
});
module.exports = __toCommonJS(src_exports);

// src/getSmithyContext.ts
var import_types = __nccwpck_require__(5756);
var getSmithyContext = /* @__PURE__ */ __name((context) => context[import_types.SMITHY_CONTEXT_KEY] || (context[import_types.SMITHY_CONTEXT_KEY] = {}), "getSmithyContext");

// src/normalizeProvider.ts
var normalizeProvider = /* @__PURE__ */ __name((input) => {
  if (typeof input === "function")
    return input;
  const promisified = Promise.resolve(input);
  return () => promisified;
}, "normalizeProvider");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 4902:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  AdaptiveRetryStrategy: () => AdaptiveRetryStrategy,
  ConfiguredRetryStrategy: () => ConfiguredRetryStrategy,
  DEFAULT_MAX_ATTEMPTS: () => DEFAULT_MAX_ATTEMPTS,
  DEFAULT_RETRY_DELAY_BASE: () => DEFAULT_RETRY_DELAY_BASE,
  DEFAULT_RETRY_MODE: () => DEFAULT_RETRY_MODE,
  DefaultRateLimiter: () => DefaultRateLimiter,
  INITIAL_RETRY_TOKENS: () => INITIAL_RETRY_TOKENS,
  INVOCATION_ID_HEADER: () => INVOCATION_ID_HEADER,
  MAXIMUM_RETRY_DELAY: () => MAXIMUM_RETRY_DELAY,
  NO_RETRY_INCREMENT: () => NO_RETRY_INCREMENT,
  REQUEST_HEADER: () => REQUEST_HEADER,
  RETRY_COST: () => RETRY_COST,
  RETRY_MODES: () => RETRY_MODES,
  StandardRetryStrategy: () => StandardRetryStrategy,
  THROTTLING_RETRY_DELAY_BASE: () => THROTTLING_RETRY_DELAY_BASE,
  TIMEOUT_RETRY_COST: () => TIMEOUT_RETRY_COST
});
module.exports = __toCommonJS(src_exports);

// src/config.ts
var RETRY_MODES = /* @__PURE__ */ ((RETRY_MODES2) => {
  RETRY_MODES2["STANDARD"] = "standard";
  RETRY_MODES2["ADAPTIVE"] = "adaptive";
  return RETRY_MODES2;
})(RETRY_MODES || {});
var DEFAULT_MAX_ATTEMPTS = 3;
var DEFAULT_RETRY_MODE = "standard" /* STANDARD */;

// src/DefaultRateLimiter.ts
var import_service_error_classification = __nccwpck_require__(6375);
var _DefaultRateLimiter = class _DefaultRateLimiter {
  constructor(options) {
    // Pre-set state variables
    this.currentCapacity = 0;
    this.enabled = false;
    this.lastMaxRate = 0;
    this.measuredTxRate = 0;
    this.requestCount = 0;
    this.lastTimestamp = 0;
    this.timeWindow = 0;
    this.beta = (options == null ? void 0 : options.beta) ?? 0.7;
    this.minCapacity = (options == null ? void 0 : options.minCapacity) ?? 1;
    this.minFillRate = (options == null ? void 0 : options.minFillRate) ?? 0.5;
    this.scaleConstant = (options == null ? void 0 : options.scaleConstant) ?? 0.4;
    this.smooth = (options == null ? void 0 : options.smooth) ?? 0.8;
    const currentTimeInSeconds = this.getCurrentTimeInSeconds();
    this.lastThrottleTime = currentTimeInSeconds;
    this.lastTxRateBucket = Math.floor(this.getCurrentTimeInSeconds());
    this.fillRate = this.minFillRate;
    this.maxCapacity = this.minCapacity;
  }
  getCurrentTimeInSeconds() {
    return Date.now() / 1e3;
  }
  async getSendToken() {
    return this.acquireTokenBucket(1);
  }
  async acquireTokenBucket(amount) {
    if (!this.enabled) {
      return;
    }
    this.refillTokenBucket();
    if (amount > this.currentCapacity) {
      const delay = (amount - this.currentCapacity) / this.fillRate * 1e3;
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
    this.currentCapacity = this.currentCapacity - amount;
  }
  refillTokenBucket() {
    const timestamp = this.getCurrentTimeInSeconds();
    if (!this.lastTimestamp) {
      this.lastTimestamp = timestamp;
      return;
    }
    const fillAmount = (timestamp - this.lastTimestamp) * this.fillRate;
    this.currentCapacity = Math.min(this.maxCapacity, this.currentCapacity + fillAmount);
    this.lastTimestamp = timestamp;
  }
  updateClientSendingRate(response) {
    let calculatedRate;
    this.updateMeasuredRate();
    if ((0, import_service_error_classification.isThrottlingError)(response)) {
      const rateToUse = !this.enabled ? this.measuredTxRate : Math.min(this.measuredTxRate, this.fillRate);
      this.lastMaxRate = rateToUse;
      this.calculateTimeWindow();
      this.lastThrottleTime = this.getCurrentTimeInSeconds();
      calculatedRate = this.cubicThrottle(rateToUse);
      this.enableTokenBucket();
    } else {
      this.calculateTimeWindow();
      calculatedRate = this.cubicSuccess(this.getCurrentTimeInSeconds());
    }
    const newRate = Math.min(calculatedRate, 2 * this.measuredTxRate);
    this.updateTokenBucketRate(newRate);
  }
  calculateTimeWindow() {
    this.timeWindow = this.getPrecise(Math.pow(this.lastMaxRate * (1 - this.beta) / this.scaleConstant, 1 / 3));
  }
  cubicThrottle(rateToUse) {
    return this.getPrecise(rateToUse * this.beta);
  }
  cubicSuccess(timestamp) {
    return this.getPrecise(
      this.scaleConstant * Math.pow(timestamp - this.lastThrottleTime - this.timeWindow, 3) + this.lastMaxRate
    );
  }
  enableTokenBucket() {
    this.enabled = true;
  }
  updateTokenBucketRate(newRate) {
    this.refillTokenBucket();
    this.fillRate = Math.max(newRate, this.minFillRate);
    this.maxCapacity = Math.max(newRate, this.minCapacity);
    this.currentCapacity = Math.min(this.currentCapacity, this.maxCapacity);
  }
  updateMeasuredRate() {
    const t = this.getCurrentTimeInSeconds();
    const timeBucket = Math.floor(t * 2) / 2;
    this.requestCount++;
    if (timeBucket > this.lastTxRateBucket) {
      const currentRate = this.requestCount / (timeBucket - this.lastTxRateBucket);
      this.measuredTxRate = this.getPrecise(currentRate * this.smooth + this.measuredTxRate * (1 - this.smooth));
      this.requestCount = 0;
      this.lastTxRateBucket = timeBucket;
    }
  }
  getPrecise(num) {
    return parseFloat(num.toFixed(8));
  }
};
__name(_DefaultRateLimiter, "DefaultRateLimiter");
var DefaultRateLimiter = _DefaultRateLimiter;

// src/constants.ts
var DEFAULT_RETRY_DELAY_BASE = 100;
var MAXIMUM_RETRY_DELAY = 20 * 1e3;
var THROTTLING_RETRY_DELAY_BASE = 500;
var INITIAL_RETRY_TOKENS = 500;
var RETRY_COST = 5;
var TIMEOUT_RETRY_COST = 10;
var NO_RETRY_INCREMENT = 1;
var INVOCATION_ID_HEADER = "amz-sdk-invocation-id";
var REQUEST_HEADER = "amz-sdk-request";

// src/defaultRetryBackoffStrategy.ts
var getDefaultRetryBackoffStrategy = /* @__PURE__ */ __name(() => {
  let delayBase = DEFAULT_RETRY_DELAY_BASE;
  const computeNextBackoffDelay = /* @__PURE__ */ __name((attempts) => {
    return Math.floor(Math.min(MAXIMUM_RETRY_DELAY, Math.random() * 2 ** attempts * delayBase));
  }, "computeNextBackoffDelay");
  const setDelayBase = /* @__PURE__ */ __name((delay) => {
    delayBase = delay;
  }, "setDelayBase");
  return {
    computeNextBackoffDelay,
    setDelayBase
  };
}, "getDefaultRetryBackoffStrategy");

// src/defaultRetryToken.ts
var createDefaultRetryToken = /* @__PURE__ */ __name(({
  retryDelay,
  retryCount,
  retryCost
}) => {
  const getRetryCount = /* @__PURE__ */ __name(() => retryCount, "getRetryCount");
  const getRetryDelay = /* @__PURE__ */ __name(() => Math.min(MAXIMUM_RETRY_DELAY, retryDelay), "getRetryDelay");
  const getRetryCost = /* @__PURE__ */ __name(() => retryCost, "getRetryCost");
  return {
    getRetryCount,
    getRetryDelay,
    getRetryCost
  };
}, "createDefaultRetryToken");

// src/StandardRetryStrategy.ts
var _StandardRetryStrategy = class _StandardRetryStrategy {
  constructor(maxAttempts) {
    this.maxAttempts = maxAttempts;
    this.mode = "standard" /* STANDARD */;
    this.capacity = INITIAL_RETRY_TOKENS;
    this.retryBackoffStrategy = getDefaultRetryBackoffStrategy();
    this.maxAttemptsProvider = typeof maxAttempts === "function" ? maxAttempts : async () => maxAttempts;
  }
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async acquireInitialRetryToken(retryTokenScope) {
    return createDefaultRetryToken({
      retryDelay: DEFAULT_RETRY_DELAY_BASE,
      retryCount: 0
    });
  }
  async refreshRetryTokenForRetry(token, errorInfo) {
    const maxAttempts = await this.getMaxAttempts();
    if (this.shouldRetry(token, errorInfo, maxAttempts)) {
      const errorType = errorInfo.errorType;
      this.retryBackoffStrategy.setDelayBase(
        errorType === "THROTTLING" ? THROTTLING_RETRY_DELAY_BASE : DEFAULT_RETRY_DELAY_BASE
      );
      const delayFromErrorType = this.retryBackoffStrategy.computeNextBackoffDelay(token.getRetryCount());
      const retryDelay = errorInfo.retryAfterHint ? Math.max(errorInfo.retryAfterHint.getTime() - Date.now() || 0, delayFromErrorType) : delayFromErrorType;
      const capacityCost = this.getCapacityCost(errorType);
      this.capacity -= capacityCost;
      return createDefaultRetryToken({
        retryDelay,
        retryCount: token.getRetryCount() + 1,
        retryCost: capacityCost
      });
    }
    throw new Error("No retry token available");
  }
  recordSuccess(token) {
    this.capacity = Math.max(INITIAL_RETRY_TOKENS, this.capacity + (token.getRetryCost() ?? NO_RETRY_INCREMENT));
  }
  /**
   * @returns the current available retry capacity.
   *
   * This number decreases when retries are executed and refills when requests or retries succeed.
   */
  getCapacity() {
    return this.capacity;
  }
  async getMaxAttempts() {
    try {
      return await this.maxAttemptsProvider();
    } catch (error) {
      console.warn(`Max attempts provider could not resolve. Using default of ${DEFAULT_MAX_ATTEMPTS}`);
      return DEFAULT_MAX_ATTEMPTS;
    }
  }
  shouldRetry(tokenToRenew, errorInfo, maxAttempts) {
    const attempts = tokenToRenew.getRetryCount() + 1;
    return attempts < maxAttempts && this.capacity >= this.getCapacityCost(errorInfo.errorType) && this.isRetryableError(errorInfo.errorType);
  }
  getCapacityCost(errorType) {
    return errorType === "TRANSIENT" ? TIMEOUT_RETRY_COST : RETRY_COST;
  }
  isRetryableError(errorType) {
    return errorType === "THROTTLING" || errorType === "TRANSIENT";
  }
};
__name(_StandardRetryStrategy, "StandardRetryStrategy");
var StandardRetryStrategy = _StandardRetryStrategy;

// src/AdaptiveRetryStrategy.ts
var _AdaptiveRetryStrategy = class _AdaptiveRetryStrategy {
  constructor(maxAttemptsProvider, options) {
    this.maxAttemptsProvider = maxAttemptsProvider;
    this.mode = "adaptive" /* ADAPTIVE */;
    const { rateLimiter } = options ?? {};
    this.rateLimiter = rateLimiter ?? new DefaultRateLimiter();
    this.standardRetryStrategy = new StandardRetryStrategy(maxAttemptsProvider);
  }
  async acquireInitialRetryToken(retryTokenScope) {
    await this.rateLimiter.getSendToken();
    return this.standardRetryStrategy.acquireInitialRetryToken(retryTokenScope);
  }
  async refreshRetryTokenForRetry(tokenToRenew, errorInfo) {
    this.rateLimiter.updateClientSendingRate(errorInfo);
    return this.standardRetryStrategy.refreshRetryTokenForRetry(tokenToRenew, errorInfo);
  }
  recordSuccess(token) {
    this.rateLimiter.updateClientSendingRate({});
    this.standardRetryStrategy.recordSuccess(token);
  }
};
__name(_AdaptiveRetryStrategy, "AdaptiveRetryStrategy");
var AdaptiveRetryStrategy = _AdaptiveRetryStrategy;

// src/ConfiguredRetryStrategy.ts
var _ConfiguredRetryStrategy = class _ConfiguredRetryStrategy extends StandardRetryStrategy {
  /**
   * @param maxAttempts - the maximum number of retry attempts allowed.
   *                      e.g., if set to 3, then 4 total requests are possible.
   * @param computeNextBackoffDelay - a millisecond delay for each retry or a function that takes the retry attempt
   *                                  and returns the delay.
   *
   * @example exponential backoff.
   * ```js
   * new Client({
   *   retryStrategy: new ConfiguredRetryStrategy(3, (attempt) => attempt ** 2)
   * });
   * ```
   * @example constant delay.
   * ```js
   * new Client({
   *   retryStrategy: new ConfiguredRetryStrategy(3, 2000)
   * });
   * ```
   */
  constructor(maxAttempts, computeNextBackoffDelay = DEFAULT_RETRY_DELAY_BASE) {
    super(typeof maxAttempts === "function" ? maxAttempts : async () => maxAttempts);
    if (typeof computeNextBackoffDelay === "number") {
      this.computeNextBackoffDelay = () => computeNextBackoffDelay;
    } else {
      this.computeNextBackoffDelay = computeNextBackoffDelay;
    }
  }
  async refreshRetryTokenForRetry(tokenToRenew, errorInfo) {
    const token = await super.refreshRetryTokenForRetry(tokenToRenew, errorInfo);
    token.getRetryDelay = () => this.computeNextBackoffDelay(token.getRetryCount());
    return token;
  }
};
__name(_ConfiguredRetryStrategy, "ConfiguredRetryStrategy");
var ConfiguredRetryStrategy = _ConfiguredRetryStrategy;
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 3636:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.getAwsChunkedEncodingStream = void 0;
const stream_1 = __nccwpck_require__(2781);
const getAwsChunkedEncodingStream = (readableStream, options) => {
    const { base64Encoder, bodyLengthChecker, checksumAlgorithmFn, checksumLocationName, streamHasher } = options;
    const checksumRequired = base64Encoder !== undefined &&
        checksumAlgorithmFn !== undefined &&
        checksumLocationName !== undefined &&
        streamHasher !== undefined;
    const digest = checksumRequired ? streamHasher(checksumAlgorithmFn, readableStream) : undefined;
    const awsChunkedEncodingStream = new stream_1.Readable({ read: () => { } });
    readableStream.on("data", (data) => {
        const length = bodyLengthChecker(data) || 0;
        awsChunkedEncodingStream.push(`${length.toString(16)}\r\n`);
        awsChunkedEncodingStream.push(data);
        awsChunkedEncodingStream.push("\r\n");
    });
    readableStream.on("end", async () => {
        awsChunkedEncodingStream.push(`0\r\n`);
        if (checksumRequired) {
            const checksum = base64Encoder(await digest);
            awsChunkedEncodingStream.push(`${checksumLocationName}:${checksum}\r\n`);
            awsChunkedEncodingStream.push(`\r\n`);
        }
        awsChunkedEncodingStream.push(null);
    });
    return awsChunkedEncodingStream;
};
exports.getAwsChunkedEncodingStream = getAwsChunkedEncodingStream;


/***/ }),

/***/ 6711:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.headStream = void 0;
async function headStream(stream, bytes) {
    var _a;
    let byteLengthCounter = 0;
    const chunks = [];
    const reader = stream.getReader();
    let isDone = false;
    while (!isDone) {
        const { done, value } = await reader.read();
        if (value) {
            chunks.push(value);
            byteLengthCounter += (_a = value === null || value === void 0 ? void 0 : value.byteLength) !== null && _a !== void 0 ? _a : 0;
        }
        if (byteLengthCounter >= bytes) {
            break;
        }
        isDone = done;
    }
    reader.releaseLock();
    const collected = new Uint8Array(Math.min(bytes, byteLengthCounter));
    let offset = 0;
    for (const chunk of chunks) {
        if (chunk.byteLength > collected.byteLength - offset) {
            collected.set(chunk.subarray(0, collected.byteLength - offset), offset);
            break;
        }
        else {
            collected.set(chunk, offset);
        }
        offset += chunk.length;
    }
    return collected;
}
exports.headStream = headStream;


/***/ }),

/***/ 6708:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.headStream = void 0;
const stream_1 = __nccwpck_require__(2781);
const headStream_browser_1 = __nccwpck_require__(6711);
const stream_type_check_1 = __nccwpck_require__(7578);
const headStream = (stream, bytes) => {
    if ((0, stream_type_check_1.isReadableStream)(stream)) {
        return (0, headStream_browser_1.headStream)(stream, bytes);
    }
    return new Promise((resolve, reject) => {
        const collector = new Collector();
        collector.limit = bytes;
        stream.pipe(collector);
        stream.on("error", (err) => {
            collector.end();
            reject(err);
        });
        collector.on("error", reject);
        collector.on("finish", function () {
            const bytes = new Uint8Array(Buffer.concat(this.buffers));
            resolve(bytes);
        });
    });
};
exports.headStream = headStream;
class Collector extends stream_1.Writable {
    constructor() {
        super(...arguments);
        this.buffers = [];
        this.limit = Infinity;
        this.bytesBuffered = 0;
    }
    _write(chunk, encoding, callback) {
        var _a;
        this.buffers.push(chunk);
        this.bytesBuffered += (_a = chunk.byteLength) !== null && _a !== void 0 ? _a : 0;
        if (this.bytesBuffered >= this.limit) {
            const excess = this.bytesBuffered - this.limit;
            const tailBuffer = this.buffers[this.buffers.length - 1];
            this.buffers[this.buffers.length - 1] = tailBuffer.subarray(0, tailBuffer.byteLength - excess);
            this.emit("finish");
        }
        callback();
    }
}


/***/ }),

/***/ 6607:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __reExport = (target, mod, secondTarget) => (__copyProps(target, mod, "default"), secondTarget && __copyProps(secondTarget, mod, "default"));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  Uint8ArrayBlobAdapter: () => Uint8ArrayBlobAdapter
});
module.exports = __toCommonJS(src_exports);

// src/blob/transforms.ts
var import_util_base64 = __nccwpck_require__(5600);
var import_util_utf8 = __nccwpck_require__(1895);
function transformToString(payload, encoding = "utf-8") {
  if (encoding === "base64") {
    return (0, import_util_base64.toBase64)(payload);
  }
  return (0, import_util_utf8.toUtf8)(payload);
}
__name(transformToString, "transformToString");
function transformFromString(str, encoding) {
  if (encoding === "base64") {
    return Uint8ArrayBlobAdapter.mutate((0, import_util_base64.fromBase64)(str));
  }
  return Uint8ArrayBlobAdapter.mutate((0, import_util_utf8.fromUtf8)(str));
}
__name(transformFromString, "transformFromString");

// src/blob/Uint8ArrayBlobAdapter.ts
var _Uint8ArrayBlobAdapter = class _Uint8ArrayBlobAdapter extends Uint8Array {
  /**
   * @param source - such as a string or Stream.
   * @returns a new Uint8ArrayBlobAdapter extending Uint8Array.
   */
  static fromString(source, encoding = "utf-8") {
    switch (typeof source) {
      case "string":
        return transformFromString(source, encoding);
      default:
        throw new Error(`Unsupported conversion from ${typeof source} to Uint8ArrayBlobAdapter.`);
    }
  }
  /**
   * @param source - Uint8Array to be mutated.
   * @returns the same Uint8Array but with prototype switched to Uint8ArrayBlobAdapter.
   */
  static mutate(source) {
    Object.setPrototypeOf(source, _Uint8ArrayBlobAdapter.prototype);
    return source;
  }
  /**
   * @param encoding - default 'utf-8'.
   * @returns the blob as string.
   */
  transformToString(encoding = "utf-8") {
    return transformToString(this, encoding);
  }
};
__name(_Uint8ArrayBlobAdapter, "Uint8ArrayBlobAdapter");
var Uint8ArrayBlobAdapter = _Uint8ArrayBlobAdapter;

// src/index.ts
__reExport(src_exports, __nccwpck_require__(3636), module.exports);
__reExport(src_exports, __nccwpck_require__(4515), module.exports);
__reExport(src_exports, __nccwpck_require__(8321), module.exports);
__reExport(src_exports, __nccwpck_require__(6708), module.exports);
__reExport(src_exports, __nccwpck_require__(7578), module.exports);
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 2942:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.sdkStreamMixin = void 0;
const fetch_http_handler_1 = __nccwpck_require__(2687);
const util_base64_1 = __nccwpck_require__(5600);
const util_hex_encoding_1 = __nccwpck_require__(5364);
const util_utf8_1 = __nccwpck_require__(1895);
const stream_type_check_1 = __nccwpck_require__(7578);
const ERR_MSG_STREAM_HAS_BEEN_TRANSFORMED = "The stream has already been transformed.";
const sdkStreamMixin = (stream) => {
    var _a, _b;
    if (!isBlobInstance(stream) && !(0, stream_type_check_1.isReadableStream)(stream)) {
        const name = ((_b = (_a = stream === null || stream === void 0 ? void 0 : stream.__proto__) === null || _a === void 0 ? void 0 : _a.constructor) === null || _b === void 0 ? void 0 : _b.name) || stream;
        throw new Error(`Unexpected stream implementation, expect Blob or ReadableStream, got ${name}`);
    }
    let transformed = false;
    const transformToByteArray = async () => {
        if (transformed) {
            throw new Error(ERR_MSG_STREAM_HAS_BEEN_TRANSFORMED);
        }
        transformed = true;
        return await (0, fetch_http_handler_1.streamCollector)(stream);
    };
    const blobToWebStream = (blob) => {
        if (typeof blob.stream !== "function") {
            throw new Error("Cannot transform payload Blob to web stream. Please make sure the Blob.stream() is polyfilled.\n" +
                "If you are using React Native, this API is not yet supported, see: https://react-native.canny.io/feature-requests/p/fetch-streaming-body");
        }
        return blob.stream();
    };
    return Object.assign(stream, {
        transformToByteArray: transformToByteArray,
        transformToString: async (encoding) => {
            const buf = await transformToByteArray();
            if (encoding === "base64") {
                return (0, util_base64_1.toBase64)(buf);
            }
            else if (encoding === "hex") {
                return (0, util_hex_encoding_1.toHex)(buf);
            }
            else if (encoding === undefined || encoding === "utf8" || encoding === "utf-8") {
                return (0, util_utf8_1.toUtf8)(buf);
            }
            else if (typeof TextDecoder === "function") {
                return new TextDecoder(encoding).decode(buf);
            }
            else {
                throw new Error("TextDecoder is not available, please make sure polyfill is provided.");
            }
        },
        transformToWebStream: () => {
            if (transformed) {
                throw new Error(ERR_MSG_STREAM_HAS_BEEN_TRANSFORMED);
            }
            transformed = true;
            if (isBlobInstance(stream)) {
                return blobToWebStream(stream);
            }
            else if ((0, stream_type_check_1.isReadableStream)(stream)) {
                return stream;
            }
            else {
                throw new Error(`Cannot transform payload to web stream, got ${stream}`);
            }
        },
    });
};
exports.sdkStreamMixin = sdkStreamMixin;
const isBlobInstance = (stream) => typeof Blob === "function" && stream instanceof Blob;


/***/ }),

/***/ 4515:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.sdkStreamMixin = void 0;
const node_http_handler_1 = __nccwpck_require__(258);
const util_buffer_from_1 = __nccwpck_require__(1381);
const stream_1 = __nccwpck_require__(2781);
const util_1 = __nccwpck_require__(3837);
const sdk_stream_mixin_browser_1 = __nccwpck_require__(2942);
const ERR_MSG_STREAM_HAS_BEEN_TRANSFORMED = "The stream has already been transformed.";
const sdkStreamMixin = (stream) => {
    var _a, _b;
    if (!(stream instanceof stream_1.Readable)) {
        try {
            return (0, sdk_stream_mixin_browser_1.sdkStreamMixin)(stream);
        }
        catch (e) {
            const name = ((_b = (_a = stream === null || stream === void 0 ? void 0 : stream.__proto__) === null || _a === void 0 ? void 0 : _a.constructor) === null || _b === void 0 ? void 0 : _b.name) || stream;
            throw new Error(`Unexpected stream implementation, expect Stream.Readable instance, got ${name}`);
        }
    }
    let transformed = false;
    const transformToByteArray = async () => {
        if (transformed) {
            throw new Error(ERR_MSG_STREAM_HAS_BEEN_TRANSFORMED);
        }
        transformed = true;
        return await (0, node_http_handler_1.streamCollector)(stream);
    };
    return Object.assign(stream, {
        transformToByteArray,
        transformToString: async (encoding) => {
            const buf = await transformToByteArray();
            if (encoding === undefined || Buffer.isEncoding(encoding)) {
                return (0, util_buffer_from_1.fromArrayBuffer)(buf.buffer, buf.byteOffset, buf.byteLength).toString(encoding);
            }
            else {
                const decoder = new util_1.TextDecoder(encoding);
                return decoder.decode(buf);
            }
        },
        transformToWebStream: () => {
            if (transformed) {
                throw new Error(ERR_MSG_STREAM_HAS_BEEN_TRANSFORMED);
            }
            if (stream.readableFlowing !== null) {
                throw new Error("The stream has been consumed by other callbacks.");
            }
            if (typeof stream_1.Readable.toWeb !== "function") {
                throw new Error("Readable.toWeb() is not supported. Please make sure you are using Node.js >= 17.0.0, or polyfill is available.");
            }
            transformed = true;
            return stream_1.Readable.toWeb(stream);
        },
    });
};
exports.sdkStreamMixin = sdkStreamMixin;


/***/ }),

/***/ 4693:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.splitStream = void 0;
async function splitStream(stream) {
    if (typeof stream.stream === "function") {
        stream = stream.stream();
    }
    const readableStream = stream;
    return readableStream.tee();
}
exports.splitStream = splitStream;


/***/ }),

/***/ 8321:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.splitStream = void 0;
const stream_1 = __nccwpck_require__(2781);
const splitStream_browser_1 = __nccwpck_require__(4693);
const stream_type_check_1 = __nccwpck_require__(7578);
async function splitStream(stream) {
    if ((0, stream_type_check_1.isReadableStream)(stream)) {
        return (0, splitStream_browser_1.splitStream)(stream);
    }
    const stream1 = new stream_1.PassThrough();
    const stream2 = new stream_1.PassThrough();
    stream.pipe(stream1);
    stream.pipe(stream2);
    return [stream1, stream2];
}
exports.splitStream = splitStream;


/***/ }),

/***/ 7578:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.isReadableStream = void 0;
const isReadableStream = (stream) => {
    var _a;
    return typeof ReadableStream === "function" &&
        (((_a = stream === null || stream === void 0 ? void 0 : stream.constructor) === null || _a === void 0 ? void 0 : _a.name) === ReadableStream.name || stream instanceof ReadableStream);
};
exports.isReadableStream = isReadableStream;


/***/ }),

/***/ 4197:
/***/ ((module) => {

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  escapeUri: () => escapeUri,
  escapeUriPath: () => escapeUriPath
});
module.exports = __toCommonJS(src_exports);

// src/escape-uri.ts
var escapeUri = /* @__PURE__ */ __name((uri) => (
  // AWS percent-encodes some extra non-standard characters in a URI
  encodeURIComponent(uri).replace(/[!'()*]/g, hexEncode)
), "escapeUri");
var hexEncode = /* @__PURE__ */ __name((c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`, "hexEncode");

// src/escape-uri-path.ts
var escapeUriPath = /* @__PURE__ */ __name((uri) => uri.split("/").map(escapeUri).join("/"), "escapeUriPath");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 1895:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  fromUtf8: () => fromUtf8,
  toUint8Array: () => toUint8Array,
  toUtf8: () => toUtf8
});
module.exports = __toCommonJS(src_exports);

// src/fromUtf8.ts
var import_util_buffer_from = __nccwpck_require__(1381);
var fromUtf8 = /* @__PURE__ */ __name((input) => {
  const buf = (0, import_util_buffer_from.fromString)(input, "utf8");
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength / Uint8Array.BYTES_PER_ELEMENT);
}, "fromUtf8");

// src/toUint8Array.ts
var toUint8Array = /* @__PURE__ */ __name((data) => {
  if (typeof data === "string") {
    return fromUtf8(data);
  }
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength / Uint8Array.BYTES_PER_ELEMENT);
  }
  return new Uint8Array(data);
}, "toUint8Array");

// src/toUtf8.ts

var toUtf8 = /* @__PURE__ */ __name((input) => {
  if (typeof input === "string") {
    return input;
  }
  if (typeof input !== "object" || typeof input.byteOffset !== "number" || typeof input.byteLength !== "number") {
    throw new Error("@smithy/util-utf8: toUtf8 encoder function only accepts string | Uint8Array.");
  }
  return (0, import_util_buffer_from.fromArrayBuffer)(input.buffer, input.byteOffset, input.byteLength).toString("utf8");
}, "toUtf8");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 8011:
/***/ ((module) => {

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  WaiterState: () => WaiterState,
  checkExceptions: () => checkExceptions,
  createWaiter: () => createWaiter,
  waiterServiceDefaults: () => waiterServiceDefaults
});
module.exports = __toCommonJS(src_exports);

// src/utils/sleep.ts
var sleep = /* @__PURE__ */ __name((seconds) => {
  return new Promise((resolve) => setTimeout(resolve, seconds * 1e3));
}, "sleep");

// src/waiter.ts
var waiterServiceDefaults = {
  minDelay: 2,
  maxDelay: 120
};
var WaiterState = /* @__PURE__ */ ((WaiterState2) => {
  WaiterState2["ABORTED"] = "ABORTED";
  WaiterState2["FAILURE"] = "FAILURE";
  WaiterState2["SUCCESS"] = "SUCCESS";
  WaiterState2["RETRY"] = "RETRY";
  WaiterState2["TIMEOUT"] = "TIMEOUT";
  return WaiterState2;
})(WaiterState || {});
var checkExceptions = /* @__PURE__ */ __name((result) => {
  if (result.state === "ABORTED" /* ABORTED */) {
    const abortError = new Error(
      `${JSON.stringify({
        ...result,
        reason: "Request was aborted"
      })}`
    );
    abortError.name = "AbortError";
    throw abortError;
  } else if (result.state === "TIMEOUT" /* TIMEOUT */) {
    const timeoutError = new Error(
      `${JSON.stringify({
        ...result,
        reason: "Waiter has timed out"
      })}`
    );
    timeoutError.name = "TimeoutError";
    throw timeoutError;
  } else if (result.state !== "SUCCESS" /* SUCCESS */) {
    throw new Error(`${JSON.stringify(result)}`);
  }
  return result;
}, "checkExceptions");

// src/poller.ts
var exponentialBackoffWithJitter = /* @__PURE__ */ __name((minDelay, maxDelay, attemptCeiling, attempt) => {
  if (attempt > attemptCeiling)
    return maxDelay;
  const delay = minDelay * 2 ** (attempt - 1);
  return randomInRange(minDelay, delay);
}, "exponentialBackoffWithJitter");
var randomInRange = /* @__PURE__ */ __name((min, max) => min + Math.random() * (max - min), "randomInRange");
var runPolling = /* @__PURE__ */ __name(async ({ minDelay, maxDelay, maxWaitTime, abortController, client, abortSignal }, input, acceptorChecks) => {
  var _a;
  const { state, reason } = await acceptorChecks(client, input);
  if (state !== "RETRY" /* RETRY */) {
    return { state, reason };
  }
  let currentAttempt = 1;
  const waitUntil = Date.now() + maxWaitTime * 1e3;
  const attemptCeiling = Math.log(maxDelay / minDelay) / Math.log(2) + 1;
  while (true) {
    if (((_a = abortController == null ? void 0 : abortController.signal) == null ? void 0 : _a.aborted) || (abortSignal == null ? void 0 : abortSignal.aborted)) {
      return { state: "ABORTED" /* ABORTED */ };
    }
    const delay = exponentialBackoffWithJitter(minDelay, maxDelay, attemptCeiling, currentAttempt);
    if (Date.now() + delay * 1e3 > waitUntil) {
      return { state: "TIMEOUT" /* TIMEOUT */ };
    }
    await sleep(delay);
    const { state: state2, reason: reason2 } = await acceptorChecks(client, input);
    if (state2 !== "RETRY" /* RETRY */) {
      return { state: state2, reason: reason2 };
    }
    currentAttempt += 1;
  }
}, "runPolling");

// src/utils/validate.ts
var validateWaiterOptions = /* @__PURE__ */ __name((options) => {
  if (options.maxWaitTime < 1) {
    throw new Error(`WaiterConfiguration.maxWaitTime must be greater than 0`);
  } else if (options.minDelay < 1) {
    throw new Error(`WaiterConfiguration.minDelay must be greater than 0`);
  } else if (options.maxDelay < 1) {
    throw new Error(`WaiterConfiguration.maxDelay must be greater than 0`);
  } else if (options.maxWaitTime <= options.minDelay) {
    throw new Error(
      `WaiterConfiguration.maxWaitTime [${options.maxWaitTime}] must be greater than WaiterConfiguration.minDelay [${options.minDelay}] for this waiter`
    );
  } else if (options.maxDelay < options.minDelay) {
    throw new Error(
      `WaiterConfiguration.maxDelay [${options.maxDelay}] must be greater than WaiterConfiguration.minDelay [${options.minDelay}] for this waiter`
    );
  }
}, "validateWaiterOptions");

// src/createWaiter.ts
var abortTimeout = /* @__PURE__ */ __name(async (abortSignal) => {
  return new Promise((resolve) => {
    const onAbort = /* @__PURE__ */ __name(() => resolve({ state: "ABORTED" /* ABORTED */ }), "onAbort");
    if (typeof abortSignal.addEventListener === "function") {
      abortSignal.addEventListener("abort", onAbort);
    } else {
      abortSignal.onabort = onAbort;
    }
  });
}, "abortTimeout");
var createWaiter = /* @__PURE__ */ __name(async (options, input, acceptorChecks) => {
  const params = {
    ...waiterServiceDefaults,
    ...options
  };
  validateWaiterOptions(params);
  const exitConditions = [runPolling(params, input, acceptorChecks)];
  if (options.abortController) {
    exitConditions.push(abortTimeout(options.abortController.signal));
  }
  if (options.abortSignal) {
    exitConditions.push(abortTimeout(options.abortSignal));
  }
  return Promise.race(exitConditions);
}, "createWaiter");
// Annotate the CommonJS export names for ESM import in node:

0 && (0);



/***/ }),

/***/ 2603:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const validator = __nccwpck_require__(1739);
const XMLParser = __nccwpck_require__(2380);
const XMLBuilder = __nccwpck_require__(660);

module.exports = {
  XMLParser: XMLParser,
  XMLValidator: validator,
  XMLBuilder: XMLBuilder
}

/***/ }),

/***/ 8280:
/***/ ((__unused_webpack_module, exports) => {

"use strict";


const nameStartChar = ':A-Za-z_\\u00C0-\\u00D6\\u00D8-\\u00F6\\u00F8-\\u02FF\\u0370-\\u037D\\u037F-\\u1FFF\\u200C-\\u200D\\u2070-\\u218F\\u2C00-\\u2FEF\\u3001-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFFD';
const nameChar = nameStartChar + '\\-.\\d\\u00B7\\u0300-\\u036F\\u203F-\\u2040';
const nameRegexp = '[' + nameStartChar + '][' + nameChar + ']*'
const regexName = new RegExp('^' + nameRegexp + '$');

const getAllMatches = function(string, regex) {
  const matches = [];
  let match = regex.exec(string);
  while (match) {
    const allmatches = [];
    allmatches.startIndex = regex.lastIndex - match[0].length;
    const len = match.length;
    for (let index = 0; index < len; index++) {
      allmatches.push(match[index]);
    }
    matches.push(allmatches);
    match = regex.exec(string);
  }
  return matches;
};

const isName = function(string) {
  const match = regexName.exec(string);
  return !(match === null || typeof match === 'undefined');
};

exports.isExist = function(v) {
  return typeof v !== 'undefined';
};

exports.isEmptyObject = function(obj) {
  return Object.keys(obj).length === 0;
};

/**
 * Copy all the properties of a into b.
 * @param {*} target
 * @param {*} a
 */
exports.merge = function(target, a, arrayMode) {
  if (a) {
    const keys = Object.keys(a); // will return an array of own properties
    const len = keys.length; //don't make it inline
    for (let i = 0; i < len; i++) {
      if (arrayMode === 'strict') {
        target[keys[i]] = [ a[keys[i]] ];
      } else {
        target[keys[i]] = a[keys[i]];
      }
    }
  }
};
/* exports.merge =function (b,a){
  return Object.assign(b,a);
} */

exports.getValue = function(v) {
  if (exports.isExist(v)) {
    return v;
  } else {
    return '';
  }
};

// const fakeCall = function(a) {return a;};
// const fakeCallNoReturn = function() {};

exports.isName = isName;
exports.getAllMatches = getAllMatches;
exports.nameRegexp = nameRegexp;


/***/ }),

/***/ 1739:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


const util = __nccwpck_require__(8280);

const defaultOptions = {
  allowBooleanAttributes: false, //A tag can have attributes without any value
  unpairedTags: []
};

//const tagsPattern = new RegExp("<\\/?([\\w:\\-_\.]+)\\s*\/?>","g");
exports.validate = function (xmlData, options) {
  options = Object.assign({}, defaultOptions, options);

  //xmlData = xmlData.replace(/(\r\n|\n|\r)/gm,"");//make it single line
  //xmlData = xmlData.replace(/(^\s*<\?xml.*?\?>)/g,"");//Remove XML starting tag
  //xmlData = xmlData.replace(/(<!DOCTYPE[\s\w\"\.\/\-\:]+(\[.*\])*\s*>)/g,"");//Remove DOCTYPE
  const tags = [];
  let tagFound = false;

  //indicates that the root tag has been closed (aka. depth 0 has been reached)
  let reachedRoot = false;

  if (xmlData[0] === '\ufeff') {
    // check for byte order mark (BOM)
    xmlData = xmlData.substr(1);
  }
  
  for (let i = 0; i < xmlData.length; i++) {

    if (xmlData[i] === '<' && xmlData[i+1] === '?') {
      i+=2;
      i = readPI(xmlData,i);
      if (i.err) return i;
    }else if (xmlData[i] === '<') {
      //starting of tag
      //read until you reach to '>' avoiding any '>' in attribute value
      let tagStartPos = i;
      i++;
      
      if (xmlData[i] === '!') {
        i = readCommentAndCDATA(xmlData, i);
        continue;
      } else {
        let closingTag = false;
        if (xmlData[i] === '/') {
          //closing tag
          closingTag = true;
          i++;
        }
        //read tagname
        let tagName = '';
        for (; i < xmlData.length &&
          xmlData[i] !== '>' &&
          xmlData[i] !== ' ' &&
          xmlData[i] !== '\t' &&
          xmlData[i] !== '\n' &&
          xmlData[i] !== '\r'; i++
        ) {
          tagName += xmlData[i];
        }
        tagName = tagName.trim();
        //console.log(tagName);

        if (tagName[tagName.length - 1] === '/') {
          //self closing tag without attributes
          tagName = tagName.substring(0, tagName.length - 1);
          //continue;
          i--;
        }
        if (!validateTagName(tagName)) {
          let msg;
          if (tagName.trim().length === 0) {
            msg = "Invalid space after '<'.";
          } else {
            msg = "Tag '"+tagName+"' is an invalid name.";
          }
          return getErrorObject('InvalidTag', msg, getLineNumberForPosition(xmlData, i));
        }

        const result = readAttributeStr(xmlData, i);
        if (result === false) {
          return getErrorObject('InvalidAttr', "Attributes for '"+tagName+"' have open quote.", getLineNumberForPosition(xmlData, i));
        }
        let attrStr = result.value;
        i = result.index;

        if (attrStr[attrStr.length - 1] === '/') {
          //self closing tag
          const attrStrStart = i - attrStr.length;
          attrStr = attrStr.substring(0, attrStr.length - 1);
          const isValid = validateAttributeString(attrStr, options);
          if (isValid === true) {
            tagFound = true;
            //continue; //text may presents after self closing tag
          } else {
            //the result from the nested function returns the position of the error within the attribute
            //in order to get the 'true' error line, we need to calculate the position where the attribute begins (i - attrStr.length) and then add the position within the attribute
            //this gives us the absolute index in the entire xml, which we can use to find the line at last
            return getErrorObject(isValid.err.code, isValid.err.msg, getLineNumberForPosition(xmlData, attrStrStart + isValid.err.line));
          }
        } else if (closingTag) {
          if (!result.tagClosed) {
            return getErrorObject('InvalidTag', "Closing tag '"+tagName+"' doesn't have proper closing.", getLineNumberForPosition(xmlData, i));
          } else if (attrStr.trim().length > 0) {
            return getErrorObject('InvalidTag', "Closing tag '"+tagName+"' can't have attributes or invalid starting.", getLineNumberForPosition(xmlData, tagStartPos));
          } else if (tags.length === 0) {
            return getErrorObject('InvalidTag', "Closing tag '"+tagName+"' has not been opened.", getLineNumberForPosition(xmlData, tagStartPos));
          } else {
            const otg = tags.pop();
            if (tagName !== otg.tagName) {
              let openPos = getLineNumberForPosition(xmlData, otg.tagStartPos);
              return getErrorObject('InvalidTag',
                "Expected closing tag '"+otg.tagName+"' (opened in line "+openPos.line+", col "+openPos.col+") instead of closing tag '"+tagName+"'.",
                getLineNumberForPosition(xmlData, tagStartPos));
            }

            //when there are no more tags, we reached the root level.
            if (tags.length == 0) {
              reachedRoot = true;
            }
          }
        } else {
          const isValid = validateAttributeString(attrStr, options);
          if (isValid !== true) {
            //the result from the nested function returns the position of the error within the attribute
            //in order to get the 'true' error line, we need to calculate the position where the attribute begins (i - attrStr.length) and then add the position within the attribute
            //this gives us the absolute index in the entire xml, which we can use to find the line at last
            return getErrorObject(isValid.err.code, isValid.err.msg, getLineNumberForPosition(xmlData, i - attrStr.length + isValid.err.line));
          }

          //if the root level has been reached before ...
          if (reachedRoot === true) {
            return getErrorObject('InvalidXml', 'Multiple possible root nodes found.', getLineNumberForPosition(xmlData, i));
          } else if(options.unpairedTags.indexOf(tagName) !== -1){
            //don't push into stack
          } else {
            tags.push({tagName, tagStartPos});
          }
          tagFound = true;
        }

        //skip tag text value
        //It may include comments and CDATA value
        for (i++; i < xmlData.length; i++) {
          if (xmlData[i] === '<') {
            if (xmlData[i + 1] === '!') {
              //comment or CADATA
              i++;
              i = readCommentAndCDATA(xmlData, i);
              continue;
            } else if (xmlData[i+1] === '?') {
              i = readPI(xmlData, ++i);
              if (i.err) return i;
            } else{
              break;
            }
          } else if (xmlData[i] === '&') {
            const afterAmp = validateAmpersand(xmlData, i);
            if (afterAmp == -1)
              return getErrorObject('InvalidChar', "char '&' is not expected.", getLineNumberForPosition(xmlData, i));
            i = afterAmp;
          }else{
            if (reachedRoot === true && !isWhiteSpace(xmlData[i])) {
              return getErrorObject('InvalidXml', "Extra text at the end", getLineNumberForPosition(xmlData, i));
            }
          }
        } //end of reading tag text value
        if (xmlData[i] === '<') {
          i--;
        }
      }
    } else {
      if ( isWhiteSpace(xmlData[i])) {
        continue;
      }
      return getErrorObject('InvalidChar', "char '"+xmlData[i]+"' is not expected.", getLineNumberForPosition(xmlData, i));
    }
  }

  if (!tagFound) {
    return getErrorObject('InvalidXml', 'Start tag expected.', 1);
  }else if (tags.length == 1) {
      return getErrorObject('InvalidTag', "Unclosed tag '"+tags[0].tagName+"'.", getLineNumberForPosition(xmlData, tags[0].tagStartPos));
  }else if (tags.length > 0) {
      return getErrorObject('InvalidXml', "Invalid '"+
          JSON.stringify(tags.map(t => t.tagName), null, 4).replace(/\r?\n/g, '')+
          "' found.", {line: 1, col: 1});
  }

  return true;
};

function isWhiteSpace(char){
  return char === ' ' || char === '\t' || char === '\n'  || char === '\r';
}
/**
 * Read Processing insstructions and skip
 * @param {*} xmlData
 * @param {*} i
 */
function readPI(xmlData, i) {
  const start = i;
  for (; i < xmlData.length; i++) {
    if (xmlData[i] == '?' || xmlData[i] == ' ') {
      //tagname
      const tagname = xmlData.substr(start, i - start);
      if (i > 5 && tagname === 'xml') {
        return getErrorObject('InvalidXml', 'XML declaration allowed only at the start of the document.', getLineNumberForPosition(xmlData, i));
      } else if (xmlData[i] == '?' && xmlData[i + 1] == '>') {
        //check if valid attribut string
        i++;
        break;
      } else {
        continue;
      }
    }
  }
  return i;
}

function readCommentAndCDATA(xmlData, i) {
  if (xmlData.length > i + 5 && xmlData[i + 1] === '-' && xmlData[i + 2] === '-') {
    //comment
    for (i += 3; i < xmlData.length; i++) {
      if (xmlData[i] === '-' && xmlData[i + 1] === '-' && xmlData[i + 2] === '>') {
        i += 2;
        break;
      }
    }
  } else if (
    xmlData.length > i + 8 &&
    xmlData[i + 1] === 'D' &&
    xmlData[i + 2] === 'O' &&
    xmlData[i + 3] === 'C' &&
    xmlData[i + 4] === 'T' &&
    xmlData[i + 5] === 'Y' &&
    xmlData[i + 6] === 'P' &&
    xmlData[i + 7] === 'E'
  ) {
    let angleBracketsCount = 1;
    for (i += 8; i < xmlData.length; i++) {
      if (xmlData[i] === '<') {
        angleBracketsCount++;
      } else if (xmlData[i] === '>') {
        angleBracketsCount--;
        if (angleBracketsCount === 0) {
          break;
        }
      }
    }
  } else if (
    xmlData.length > i + 9 &&
    xmlData[i + 1] === '[' &&
    xmlData[i + 2] === 'C' &&
    xmlData[i + 3] === 'D' &&
    xmlData[i + 4] === 'A' &&
    xmlData[i + 5] === 'T' &&
    xmlData[i + 6] === 'A' &&
    xmlData[i + 7] === '['
  ) {
    for (i += 8; i < xmlData.length; i++) {
      if (xmlData[i] === ']' && xmlData[i + 1] === ']' && xmlData[i + 2] === '>') {
        i += 2;
        break;
      }
    }
  }

  return i;
}

const doubleQuote = '"';
const singleQuote = "'";

/**
 * Keep reading xmlData until '<' is found outside the attribute value.
 * @param {string} xmlData
 * @param {number} i
 */
function readAttributeStr(xmlData, i) {
  let attrStr = '';
  let startChar = '';
  let tagClosed = false;
  for (; i < xmlData.length; i++) {
    if (xmlData[i] === doubleQuote || xmlData[i] === singleQuote) {
      if (startChar === '') {
        startChar = xmlData[i];
      } else if (startChar !== xmlData[i]) {
        //if vaue is enclosed with double quote then single quotes are allowed inside the value and vice versa
      } else {
        startChar = '';
      }
    } else if (xmlData[i] === '>') {
      if (startChar === '') {
        tagClosed = true;
        break;
      }
    }
    attrStr += xmlData[i];
  }
  if (startChar !== '') {
    return false;
  }

  return {
    value: attrStr,
    index: i,
    tagClosed: tagClosed
  };
}

/**
 * Select all the attributes whether valid or invalid.
 */
const validAttrStrRegxp = new RegExp('(\\s*)([^\\s=]+)(\\s*=)?(\\s*([\'"])(([\\s\\S])*?)\\5)?', 'g');

//attr, ="sd", a="amit's", a="sd"b="saf", ab  cd=""

function validateAttributeString(attrStr, options) {
  //console.log("start:"+attrStr+":end");

  //if(attrStr.trim().length === 0) return true; //empty string

  const matches = util.getAllMatches(attrStr, validAttrStrRegxp);
  const attrNames = {};

  for (let i = 0; i < matches.length; i++) {
    if (matches[i][1].length === 0) {
      //nospace before attribute name: a="sd"b="saf"
      return getErrorObject('InvalidAttr', "Attribute '"+matches[i][2]+"' has no space in starting.", getPositionFromMatch(matches[i]))
    } else if (matches[i][3] !== undefined && matches[i][4] === undefined) {
      return getErrorObject('InvalidAttr', "Attribute '"+matches[i][2]+"' is without value.", getPositionFromMatch(matches[i]));
    } else if (matches[i][3] === undefined && !options.allowBooleanAttributes) {
      //independent attribute: ab
      return getErrorObject('InvalidAttr', "boolean attribute '"+matches[i][2]+"' is not allowed.", getPositionFromMatch(matches[i]));
    }
    /* else if(matches[i][6] === undefined){//attribute without value: ab=
                    return { err: { code:"InvalidAttr",msg:"attribute " + matches[i][2] + " has no value assigned."}};
                } */
    const attrName = matches[i][2];
    if (!validateAttrName(attrName)) {
      return getErrorObject('InvalidAttr', "Attribute '"+attrName+"' is an invalid name.", getPositionFromMatch(matches[i]));
    }
    if (!attrNames.hasOwnProperty(attrName)) {
      //check for duplicate attribute.
      attrNames[attrName] = 1;
    } else {
      return getErrorObject('InvalidAttr', "Attribute '"+attrName+"' is repeated.", getPositionFromMatch(matches[i]));
    }
  }

  return true;
}

function validateNumberAmpersand(xmlData, i) {
  let re = /\d/;
  if (xmlData[i] === 'x') {
    i++;
    re = /[\da-fA-F]/;
  }
  for (; i < xmlData.length; i++) {
    if (xmlData[i] === ';')
      return i;
    if (!xmlData[i].match(re))
      break;
  }
  return -1;
}

function validateAmpersand(xmlData, i) {
  // https://www.w3.org/TR/xml/#dt-charref
  i++;
  if (xmlData[i] === ';')
    return -1;
  if (xmlData[i] === '#') {
    i++;
    return validateNumberAmpersand(xmlData, i);
  }
  let count = 0;
  for (; i < xmlData.length; i++, count++) {
    if (xmlData[i].match(/\w/) && count < 20)
      continue;
    if (xmlData[i] === ';')
      break;
    return -1;
  }
  return i;
}

function getErrorObject(code, message, lineNumber) {
  return {
    err: {
      code: code,
      msg: message,
      line: lineNumber.line || lineNumber,
      col: lineNumber.col,
    },
  };
}

function validateAttrName(attrName) {
  return util.isName(attrName);
}

// const startsWithXML = /^xml/i;

function validateTagName(tagname) {
  return util.isName(tagname) /* && !tagname.match(startsWithXML) */;
}

//this function returns the line number for the character at the given index
function getLineNumberForPosition(xmlData, index) {
  const lines = xmlData.substring(0, index).split(/\r?\n/);
  return {
    line: lines.length,

    // column number is last line's length + 1, because column numbering starts at 1:
    col: lines[lines.length - 1].length + 1
  };
}

//this function returns the position of the first character of match within attrStr
function getPositionFromMatch(match) {
  return match.startIndex + match[1].length;
}


/***/ }),

/***/ 660:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";

//parse Empty Node as self closing node
const buildFromOrderedJs = __nccwpck_require__(2462);

const defaultOptions = {
  attributeNamePrefix: '@_',
  attributesGroupName: false,
  textNodeName: '#text',
  ignoreAttributes: true,
  cdataPropName: false,
  format: false,
  indentBy: '  ',
  suppressEmptyNode: false,
  suppressUnpairedNode: true,
  suppressBooleanAttributes: true,
  tagValueProcessor: function(key, a) {
    return a;
  },
  attributeValueProcessor: function(attrName, a) {
    return a;
  },
  preserveOrder: false,
  commentPropName: false,
  unpairedTags: [],
  entities: [
    { regex: new RegExp("&", "g"), val: "&amp;" },//it must be on top
    { regex: new RegExp(">", "g"), val: "&gt;" },
    { regex: new RegExp("<", "g"), val: "&lt;" },
    { regex: new RegExp("\'", "g"), val: "&apos;" },
    { regex: new RegExp("\"", "g"), val: "&quot;" }
  ],
  processEntities: true,
  stopNodes: [],
  // transformTagName: false,
  // transformAttributeName: false,
  oneListGroup: false
};

function Builder(options) {
  this.options = Object.assign({}, defaultOptions, options);
  if (this.options.ignoreAttributes || this.options.attributesGroupName) {
    this.isAttribute = function(/*a*/) {
      return false;
    };
  } else {
    this.attrPrefixLen = this.options.attributeNamePrefix.length;
    this.isAttribute = isAttribute;
  }

  this.processTextOrObjNode = processTextOrObjNode

  if (this.options.format) {
    this.indentate = indentate;
    this.tagEndChar = '>\n';
    this.newLine = '\n';
  } else {
    this.indentate = function() {
      return '';
    };
    this.tagEndChar = '>';
    this.newLine = '';
  }
}

Builder.prototype.build = function(jObj) {
  if(this.options.preserveOrder){
    return buildFromOrderedJs(jObj, this.options);
  }else {
    if(Array.isArray(jObj) && this.options.arrayNodeName && this.options.arrayNodeName.length > 1){
      jObj = {
        [this.options.arrayNodeName] : jObj
      }
    }
    return this.j2x(jObj, 0).val;
  }
};

Builder.prototype.j2x = function(jObj, level) {
  let attrStr = '';
  let val = '';
  for (let key in jObj) {
    if(!Object.prototype.hasOwnProperty.call(jObj, key)) continue;
    if (typeof jObj[key] === 'undefined') {
      // supress undefined node only if it is not an attribute
      if (this.isAttribute(key)) {
        val += '';
      }
    } else if (jObj[key] === null) {
      // null attribute should be ignored by the attribute list, but should not cause the tag closing
      if (this.isAttribute(key)) {
        val += '';
      } else if (key[0] === '?') {
        val += this.indentate(level) + '<' + key + '?' + this.tagEndChar;
      } else {
        val += this.indentate(level) + '<' + key + '/' + this.tagEndChar;
      }
      // val += this.indentate(level) + '<' + key + '/' + this.tagEndChar;
    } else if (jObj[key] instanceof Date) {
      val += this.buildTextValNode(jObj[key], key, '', level);
    } else if (typeof jObj[key] !== 'object') {
      //premitive type
      const attr = this.isAttribute(key);
      if (attr) {
        attrStr += this.buildAttrPairStr(attr, '' + jObj[key]);
      }else {
        //tag value
        if (key === this.options.textNodeName) {
          let newval = this.options.tagValueProcessor(key, '' + jObj[key]);
          val += this.replaceEntitiesValue(newval);
        } else {
          val += this.buildTextValNode(jObj[key], key, '', level);
        }
      }
    } else if (Array.isArray(jObj[key])) {
      //repeated nodes
      const arrLen = jObj[key].length;
      let listTagVal = "";
      let listTagAttr = "";
      for (let j = 0; j < arrLen; j++) {
        const item = jObj[key][j];
        if (typeof item === 'undefined') {
          // supress undefined node
        } else if (item === null) {
          if(key[0] === "?") val += this.indentate(level) + '<' + key + '?' + this.tagEndChar;
          else val += this.indentate(level) + '<' + key + '/' + this.tagEndChar;
          // val += this.indentate(level) + '<' + key + '/' + this.tagEndChar;
        } else if (typeof item === 'object') {
          if(this.options.oneListGroup){
            const result = this.j2x(item, level + 1);
            listTagVal += result.val;
            if (this.options.attributesGroupName && item.hasOwnProperty(this.options.attributesGroupName)) {
              listTagAttr += result.attrStr
            }
          }else{
            listTagVal += this.processTextOrObjNode(item, key, level)
          }
        } else {
          if (this.options.oneListGroup) {
            let textValue = this.options.tagValueProcessor(key, item);
            textValue = this.replaceEntitiesValue(textValue);
            listTagVal += textValue;
          } else {
            listTagVal += this.buildTextValNode(item, key, '', level);
          }
        }
      }
      if(this.options.oneListGroup){
        listTagVal = this.buildObjectNode(listTagVal, key, listTagAttr, level);
      }
      val += listTagVal;
    } else {
      //nested node
      if (this.options.attributesGroupName && key === this.options.attributesGroupName) {
        const Ks = Object.keys(jObj[key]);
        const L = Ks.length;
        for (let j = 0; j < L; j++) {
          attrStr += this.buildAttrPairStr(Ks[j], '' + jObj[key][Ks[j]]);
        }
      } else {
        val += this.processTextOrObjNode(jObj[key], key, level)
      }
    }
  }
  return {attrStr: attrStr, val: val};
};

Builder.prototype.buildAttrPairStr = function(attrName, val){
  val = this.options.attributeValueProcessor(attrName, '' + val);
  val = this.replaceEntitiesValue(val);
  if (this.options.suppressBooleanAttributes && val === "true") {
    return ' ' + attrName;
  } else return ' ' + attrName + '="' + val + '"';
}

function processTextOrObjNode (object, key, level) {
  const result = this.j2x(object, level + 1);
  if (object[this.options.textNodeName] !== undefined && Object.keys(object).length === 1) {
    return this.buildTextValNode(object[this.options.textNodeName], key, result.attrStr, level);
  } else {
    return this.buildObjectNode(result.val, key, result.attrStr, level);
  }
}

Builder.prototype.buildObjectNode = function(val, key, attrStr, level) {
  if(val === ""){
    if(key[0] === "?") return  this.indentate(level) + '<' + key + attrStr+ '?' + this.tagEndChar;
    else {
      return this.indentate(level) + '<' + key + attrStr + this.closeTag(key) + this.tagEndChar;
    }
  }else{

    let tagEndExp = '</' + key + this.tagEndChar;
    let piClosingChar = "";
    
    if(key[0] === "?") {
      piClosingChar = "?";
      tagEndExp = "";
    }
  
    // attrStr is an empty string in case the attribute came as undefined or null
    if ((attrStr || attrStr === '') && val.indexOf('<') === -1) {
      return ( this.indentate(level) + '<' +  key + attrStr + piClosingChar + '>' + val + tagEndExp );
    } else if (this.options.commentPropName !== false && key === this.options.commentPropName && piClosingChar.length === 0) {
      return this.indentate(level) + `<!--${val}-->` + this.newLine;
    }else {
      return (
        this.indentate(level) + '<' + key + attrStr + piClosingChar + this.tagEndChar +
        val +
        this.indentate(level) + tagEndExp    );
    }
  }
}

Builder.prototype.closeTag = function(key){
  let closeTag = "";
  if(this.options.unpairedTags.indexOf(key) !== -1){ //unpaired
    if(!this.options.suppressUnpairedNode) closeTag = "/"
  }else if(this.options.suppressEmptyNode){ //empty
    closeTag = "/";
  }else{
    closeTag = `></${key}`
  }
  return closeTag;
}

function buildEmptyObjNode(val, key, attrStr, level) {
  if (val !== '') {
    return this.buildObjectNode(val, key, attrStr, level);
  } else {
    if(key[0] === "?") return  this.indentate(level) + '<' + key + attrStr+ '?' + this.tagEndChar;
    else {
      return  this.indentate(level) + '<' + key + attrStr + '/' + this.tagEndChar;
      // return this.buildTagStr(level,key, attrStr);
    }
  }
}

Builder.prototype.buildTextValNode = function(val, key, attrStr, level) {
  if (this.options.cdataPropName !== false && key === this.options.cdataPropName) {
    return this.indentate(level) + `<![CDATA[${val}]]>` +  this.newLine;
  }else if (this.options.commentPropName !== false && key === this.options.commentPropName) {
    return this.indentate(level) + `<!--${val}-->` +  this.newLine;
  }else if(key[0] === "?") {//PI tag
    return  this.indentate(level) + '<' + key + attrStr+ '?' + this.tagEndChar; 
  }else{
    let textValue = this.options.tagValueProcessor(key, val);
    textValue = this.replaceEntitiesValue(textValue);
  
    if( textValue === ''){
      return this.indentate(level) + '<' + key + attrStr + this.closeTag(key) + this.tagEndChar;
    }else{
      return this.indentate(level) + '<' + key + attrStr + '>' +
         textValue +
        '</' + key + this.tagEndChar;
    }
  }
}

Builder.prototype.replaceEntitiesValue = function(textValue){
  if(textValue && textValue.length > 0 && this.options.processEntities){
    for (let i=0; i<this.options.entities.length; i++) {
      const entity = this.options.entities[i];
      textValue = textValue.replace(entity.regex, entity.val);
    }
  }
  return textValue;
}

function indentate(level) {
  return this.options.indentBy.repeat(level);
}

function isAttribute(name /*, options*/) {
  if (name.startsWith(this.options.attributeNamePrefix) && name !== this.options.textNodeName) {
    return name.substr(this.attrPrefixLen);
  } else {
    return false;
  }
}

module.exports = Builder;


/***/ }),

/***/ 2462:
/***/ ((module) => {

const EOL = "\n";

/**
 * 
 * @param {array} jArray 
 * @param {any} options 
 * @returns 
 */
function toXml(jArray, options) {
    let indentation = "";
    if (options.format && options.indentBy.length > 0) {
        indentation = EOL;
    }
    return arrToStr(jArray, options, "", indentation);
}

function arrToStr(arr, options, jPath, indentation) {
    let xmlStr = "";
    let isPreviousElementTag = false;

    for (let i = 0; i < arr.length; i++) {
        const tagObj = arr[i];
        const tagName = propName(tagObj);
        if(tagName === undefined) continue;

        let newJPath = "";
        if (jPath.length === 0) newJPath = tagName
        else newJPath = `${jPath}.${tagName}`;

        if (tagName === options.textNodeName) {
            let tagText = tagObj[tagName];
            if (!isStopNode(newJPath, options)) {
                tagText = options.tagValueProcessor(tagName, tagText);
                tagText = replaceEntitiesValue(tagText, options);
            }
            if (isPreviousElementTag) {
                xmlStr += indentation;
            }
            xmlStr += tagText;
            isPreviousElementTag = false;
            continue;
        } else if (tagName === options.cdataPropName) {
            if (isPreviousElementTag) {
                xmlStr += indentation;
            }
            xmlStr += `<![CDATA[${tagObj[tagName][0][options.textNodeName]}]]>`;
            isPreviousElementTag = false;
            continue;
        } else if (tagName === options.commentPropName) {
            xmlStr += indentation + `<!--${tagObj[tagName][0][options.textNodeName]}-->`;
            isPreviousElementTag = true;
            continue;
        } else if (tagName[0] === "?") {
            const attStr = attr_to_str(tagObj[":@"], options);
            const tempInd = tagName === "?xml" ? "" : indentation;
            let piTextNodeName = tagObj[tagName][0][options.textNodeName];
            piTextNodeName = piTextNodeName.length !== 0 ? " " + piTextNodeName : ""; //remove extra spacing
            xmlStr += tempInd + `<${tagName}${piTextNodeName}${attStr}?>`;
            isPreviousElementTag = true;
            continue;
        }
        let newIdentation = indentation;
        if (newIdentation !== "") {
            newIdentation += options.indentBy;
        }
        const attStr = attr_to_str(tagObj[":@"], options);
        const tagStart = indentation + `<${tagName}${attStr}`;
        const tagValue = arrToStr(tagObj[tagName], options, newJPath, newIdentation);
        if (options.unpairedTags.indexOf(tagName) !== -1) {
            if (options.suppressUnpairedNode) xmlStr += tagStart + ">";
            else xmlStr += tagStart + "/>";
        } else if ((!tagValue || tagValue.length === 0) && options.suppressEmptyNode) {
            xmlStr += tagStart + "/>";
        } else if (tagValue && tagValue.endsWith(">")) {
            xmlStr += tagStart + `>${tagValue}${indentation}</${tagName}>`;
        } else {
            xmlStr += tagStart + ">";
            if (tagValue && indentation !== "" && (tagValue.includes("/>") || tagValue.includes("</"))) {
                xmlStr += indentation + options.indentBy + tagValue + indentation;
            } else {
                xmlStr += tagValue;
            }
            xmlStr += `</${tagName}>`;
        }
        isPreviousElementTag = true;
    }

    return xmlStr;
}

function propName(obj) {
    const keys = Object.keys(obj);
    for (let i = 0; i < keys.length; i++) {
        const key = keys[i];
        if(!obj.hasOwnProperty(key)) continue;
        if (key !== ":@") return key;
    }
}

function attr_to_str(attrMap, options) {
    let attrStr = "";
    if (attrMap && !options.ignoreAttributes) {
        for (let attr in attrMap) {
            if(!attrMap.hasOwnProperty(attr)) continue;
            let attrVal = options.attributeValueProcessor(attr, attrMap[attr]);
            attrVal = replaceEntitiesValue(attrVal, options);
            if (attrVal === true && options.suppressBooleanAttributes) {
                attrStr += ` ${attr.substr(options.attributeNamePrefix.length)}`;
            } else {
                attrStr += ` ${attr.substr(options.attributeNamePrefix.length)}="${attrVal}"`;
            }
        }
    }
    return attrStr;
}

function isStopNode(jPath, options) {
    jPath = jPath.substr(0, jPath.length - options.textNodeName.length - 1);
    let tagName = jPath.substr(jPath.lastIndexOf(".") + 1);
    for (let index in options.stopNodes) {
        if (options.stopNodes[index] === jPath || options.stopNodes[index] === "*." + tagName) return true;
    }
    return false;
}

function replaceEntitiesValue(textValue, options) {
    if (textValue && textValue.length > 0 && options.processEntities) {
        for (let i = 0; i < options.entities.length; i++) {
            const entity = options.entities[i];
            textValue = textValue.replace(entity.regex, entity.val);
        }
    }
    return textValue;
}
module.exports = toXml;


/***/ }),

/***/ 6072:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

const util = __nccwpck_require__(8280);

//TODO: handle comments
function readDocType(xmlData, i){
    
    const entities = {};
    if( xmlData[i + 3] === 'O' &&
         xmlData[i + 4] === 'C' &&
         xmlData[i + 5] === 'T' &&
         xmlData[i + 6] === 'Y' &&
         xmlData[i + 7] === 'P' &&
         xmlData[i + 8] === 'E')
    {    
        i = i+9;
        let angleBracketsCount = 1;
        let hasBody = false, comment = false;
        let exp = "";
        for(;i<xmlData.length;i++){
            if (xmlData[i] === '<' && !comment) { //Determine the tag type
                if( hasBody && isEntity(xmlData, i)){
                    i += 7; 
                    [entityName, val,i] = readEntityExp(xmlData,i+1);
                    if(val.indexOf("&") === -1) //Parameter entities are not supported
                        entities[ validateEntityName(entityName) ] = {
                            regx : RegExp( `&${entityName};`,"g"),
                            val: val
                        };
                }
                else if( hasBody && isElement(xmlData, i))  i += 8;//Not supported
                else if( hasBody && isAttlist(xmlData, i))  i += 8;//Not supported
                else if( hasBody && isNotation(xmlData, i)) i += 9;//Not supported
                else if( isComment)                         comment = true;
                else                                        throw new Error("Invalid DOCTYPE");

                angleBracketsCount++;
                exp = "";
            } else if (xmlData[i] === '>') { //Read tag content
                if(comment){
                    if( xmlData[i - 1] === "-" && xmlData[i - 2] === "-"){
                        comment = false;
                        angleBracketsCount--;
                    }
                }else{
                    angleBracketsCount--;
                }
                if (angleBracketsCount === 0) {
                  break;
                }
            }else if( xmlData[i] === '['){
                hasBody = true;
            }else{
                exp += xmlData[i];
            }
        }
        if(angleBracketsCount !== 0){
            throw new Error(`Unclosed DOCTYPE`);
        }
    }else{
        throw new Error(`Invalid Tag instead of DOCTYPE`);
    }
    return {entities, i};
}

function readEntityExp(xmlData,i){
    //External entities are not supported
    //    <!ENTITY ext SYSTEM "http://normal-website.com" >

    //Parameter entities are not supported
    //    <!ENTITY entityname "&anotherElement;">

    //Internal entities are supported
    //    <!ENTITY entityname "replacement text">
    
    //read EntityName
    let entityName = "";
    for (; i < xmlData.length && (xmlData[i] !== "'" && xmlData[i] !== '"' ); i++) {
        // if(xmlData[i] === " ") continue;
        // else 
        entityName += xmlData[i];
    }
    entityName = entityName.trim();
    if(entityName.indexOf(" ") !== -1) throw new Error("External entites are not supported");

    //read Entity Value
    const startChar = xmlData[i++];
    let val = ""
    for (; i < xmlData.length && xmlData[i] !== startChar ; i++) {
        val += xmlData[i];
    }
    return [entityName, val, i];
}

function isComment(xmlData, i){
    if(xmlData[i+1] === '!' &&
    xmlData[i+2] === '-' &&
    xmlData[i+3] === '-') return true
    return false
}
function isEntity(xmlData, i){
    if(xmlData[i+1] === '!' &&
    xmlData[i+2] === 'E' &&
    xmlData[i+3] === 'N' &&
    xmlData[i+4] === 'T' &&
    xmlData[i+5] === 'I' &&
    xmlData[i+6] === 'T' &&
    xmlData[i+7] === 'Y') return true
    return false
}
function isElement(xmlData, i){
    if(xmlData[i+1] === '!' &&
    xmlData[i+2] === 'E' &&
    xmlData[i+3] === 'L' &&
    xmlData[i+4] === 'E' &&
    xmlData[i+5] === 'M' &&
    xmlData[i+6] === 'E' &&
    xmlData[i+7] === 'N' &&
    xmlData[i+8] === 'T') return true
    return false
}

function isAttlist(xmlData, i){
    if(xmlData[i+1] === '!' &&
    xmlData[i+2] === 'A' &&
    xmlData[i+3] === 'T' &&
    xmlData[i+4] === 'T' &&
    xmlData[i+5] === 'L' &&
    xmlData[i+6] === 'I' &&
    xmlData[i+7] === 'S' &&
    xmlData[i+8] === 'T') return true
    return false
}
function isNotation(xmlData, i){
    if(xmlData[i+1] === '!' &&
    xmlData[i+2] === 'N' &&
    xmlData[i+3] === 'O' &&
    xmlData[i+4] === 'T' &&
    xmlData[i+5] === 'A' &&
    xmlData[i+6] === 'T' &&
    xmlData[i+7] === 'I' &&
    xmlData[i+8] === 'O' &&
    xmlData[i+9] === 'N') return true
    return false
}

function validateEntityName(name){
    if (util.isName(name))
	return name;
    else
        throw new Error(`Invalid entity name ${name}`);
}

module.exports = readDocType;


/***/ }),

/***/ 6993:
/***/ ((__unused_webpack_module, exports) => {


const defaultOptions = {
    preserveOrder: false,
    attributeNamePrefix: '@_',
    attributesGroupName: false,
    textNodeName: '#text',
    ignoreAttributes: true,
    removeNSPrefix: false, // remove NS from tag name or attribute name if true
    allowBooleanAttributes: false, //a tag can have attributes without any value
    //ignoreRootElement : false,
    parseTagValue: true,
    parseAttributeValue: false,
    trimValues: true, //Trim string values of tag and attributes
    cdataPropName: false,
    numberParseOptions: {
      hex: true,
      leadingZeros: true,
      eNotation: true
    },
    tagValueProcessor: function(tagName, val) {
      return val;
    },
    attributeValueProcessor: function(attrName, val) {
      return val;
    },
    stopNodes: [], //nested tags will not be parsed even for errors
    alwaysCreateTextNode: false,
    isArray: () => false,
    commentPropName: false,
    unpairedTags: [],
    processEntities: true,
    htmlEntities: false,
    ignoreDeclaration: false,
    ignorePiTags: false,
    transformTagName: false,
    transformAttributeName: false,
    updateTag: function(tagName, jPath, attrs){
      return tagName
    },
    // skipEmptyListItem: false
};
   
const buildOptions = function(options) {
    return Object.assign({}, defaultOptions, options);
};

exports.buildOptions = buildOptions;
exports.defaultOptions = defaultOptions;

/***/ }),

/***/ 5832:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";

///@ts-check

const util = __nccwpck_require__(8280);
const xmlNode = __nccwpck_require__(7462);
const readDocType = __nccwpck_require__(6072);
const toNumber = __nccwpck_require__(4526);

// const regx =
//   '<((!\\[CDATA\\[([\\s\\S]*?)(]]>))|((NAME:)?(NAME))([^>]*)>|((\\/)(NAME)\\s*>))([^<]*)'
//   .replace(/NAME/g, util.nameRegexp);

//const tagsRegx = new RegExp("<(\\/?[\\w:\\-\._]+)([^>]*)>(\\s*"+cdataRegx+")*([^<]+)?","g");
//const tagsRegx = new RegExp("<(\\/?)((\\w*:)?([\\w:\\-\._]+))([^>]*)>([^<]*)("+cdataRegx+"([^<]*))*([^<]+)?","g");

class OrderedObjParser{
  constructor(options){
    this.options = options;
    this.currentNode = null;
    this.tagsNodeStack = [];
    this.docTypeEntities = {};
    this.lastEntities = {
      "apos" : { regex: /&(apos|#39|#x27);/g, val : "'"},
      "gt" : { regex: /&(gt|#62|#x3E);/g, val : ">"},
      "lt" : { regex: /&(lt|#60|#x3C);/g, val : "<"},
      "quot" : { regex: /&(quot|#34|#x22);/g, val : "\""},
    };
    this.ampEntity = { regex: /&(amp|#38|#x26);/g, val : "&"};
    this.htmlEntities = {
      "space": { regex: /&(nbsp|#160);/g, val: " " },
      // "lt" : { regex: /&(lt|#60);/g, val: "<" },
      // "gt" : { regex: /&(gt|#62);/g, val: ">" },
      // "amp" : { regex: /&(amp|#38);/g, val: "&" },
      // "quot" : { regex: /&(quot|#34);/g, val: "\"" },
      // "apos" : { regex: /&(apos|#39);/g, val: "'" },
      "cent" : { regex: /&(cent|#162);/g, val: "¢" },
      "pound" : { regex: /&(pound|#163);/g, val: "£" },
      "yen" : { regex: /&(yen|#165);/g, val: "¥" },
      "euro" : { regex: /&(euro|#8364);/g, val: "€" },
      "copyright" : { regex: /&(copy|#169);/g, val: "©" },
      "reg" : { regex: /&(reg|#174);/g, val: "®" },
      "inr" : { regex: /&(inr|#8377);/g, val: "₹" },
      "num_dec": { regex: /&#([0-9]{1,7});/g, val : (_, str) => String.fromCharCode(Number.parseInt(str, 10)) },
      "num_hex": { regex: /&#x([0-9a-fA-F]{1,6});/g, val : (_, str) => String.fromCharCode(Number.parseInt(str, 16)) },
    };
    this.addExternalEntities = addExternalEntities;
    this.parseXml = parseXml;
    this.parseTextData = parseTextData;
    this.resolveNameSpace = resolveNameSpace;
    this.buildAttributesMap = buildAttributesMap;
    this.isItStopNode = isItStopNode;
    this.replaceEntitiesValue = replaceEntitiesValue;
    this.readStopNodeData = readStopNodeData;
    this.saveTextToParentTag = saveTextToParentTag;
    this.addChild = addChild;
  }

}

function addExternalEntities(externalEntities){
  const entKeys = Object.keys(externalEntities);
  for (let i = 0; i < entKeys.length; i++) {
    const ent = entKeys[i];
    this.lastEntities[ent] = {
       regex: new RegExp("&"+ent+";","g"),
       val : externalEntities[ent]
    }
  }
}

/**
 * @param {string} val
 * @param {string} tagName
 * @param {string} jPath
 * @param {boolean} dontTrim
 * @param {boolean} hasAttributes
 * @param {boolean} isLeafNode
 * @param {boolean} escapeEntities
 */
function parseTextData(val, tagName, jPath, dontTrim, hasAttributes, isLeafNode, escapeEntities) {
  if (val !== undefined) {
    if (this.options.trimValues && !dontTrim) {
      val = val.trim();
    }
    if(val.length > 0){
      if(!escapeEntities) val = this.replaceEntitiesValue(val);
      
      const newval = this.options.tagValueProcessor(tagName, val, jPath, hasAttributes, isLeafNode);
      if(newval === null || newval === undefined){
        //don't parse
        return val;
      }else if(typeof newval !== typeof val || newval !== val){
        //overwrite
        return newval;
      }else if(this.options.trimValues){
        return parseValue(val, this.options.parseTagValue, this.options.numberParseOptions);
      }else{
        const trimmedVal = val.trim();
        if(trimmedVal === val){
          return parseValue(val, this.options.parseTagValue, this.options.numberParseOptions);
        }else{
          return val;
        }
      }
    }
  }
}

function resolveNameSpace(tagname) {
  if (this.options.removeNSPrefix) {
    const tags = tagname.split(':');
    const prefix = tagname.charAt(0) === '/' ? '/' : '';
    if (tags[0] === 'xmlns') {
      return '';
    }
    if (tags.length === 2) {
      tagname = prefix + tags[1];
    }
  }
  return tagname;
}

//TODO: change regex to capture NS
//const attrsRegx = new RegExp("([\\w\\-\\.\\:]+)\\s*=\\s*(['\"])((.|\n)*?)\\2","gm");
const attrsRegx = new RegExp('([^\\s=]+)\\s*(=\\s*([\'"])([\\s\\S]*?)\\3)?', 'gm');

function buildAttributesMap(attrStr, jPath, tagName) {
  if (!this.options.ignoreAttributes && typeof attrStr === 'string') {
    // attrStr = attrStr.replace(/\r?\n/g, ' ');
    //attrStr = attrStr || attrStr.trim();

    const matches = util.getAllMatches(attrStr, attrsRegx);
    const len = matches.length; //don't make it inline
    const attrs = {};
    for (let i = 0; i < len; i++) {
      const attrName = this.resolveNameSpace(matches[i][1]);
      let oldVal = matches[i][4];
      let aName = this.options.attributeNamePrefix + attrName;
      if (attrName.length) {
        if (this.options.transformAttributeName) {
          aName = this.options.transformAttributeName(aName);
        }
        if(aName === "__proto__") aName  = "#__proto__";
        if (oldVal !== undefined) {
          if (this.options.trimValues) {
            oldVal = oldVal.trim();
          }
          oldVal = this.replaceEntitiesValue(oldVal);
          const newVal = this.options.attributeValueProcessor(attrName, oldVal, jPath);
          if(newVal === null || newVal === undefined){
            //don't parse
            attrs[aName] = oldVal;
          }else if(typeof newVal !== typeof oldVal || newVal !== oldVal){
            //overwrite
            attrs[aName] = newVal;
          }else{
            //parse
            attrs[aName] = parseValue(
              oldVal,
              this.options.parseAttributeValue,
              this.options.numberParseOptions
            );
          }
        } else if (this.options.allowBooleanAttributes) {
          attrs[aName] = true;
        }
      }
    }
    if (!Object.keys(attrs).length) {
      return;
    }
    if (this.options.attributesGroupName) {
      const attrCollection = {};
      attrCollection[this.options.attributesGroupName] = attrs;
      return attrCollection;
    }
    return attrs
  }
}

const parseXml = function(xmlData) {
  xmlData = xmlData.replace(/\r\n?/g, "\n"); //TODO: remove this line
  const xmlObj = new xmlNode('!xml');
  let currentNode = xmlObj;
  let textData = "";
  let jPath = "";
  for(let i=0; i< xmlData.length; i++){//for each char in XML data
    const ch = xmlData[i];
    if(ch === '<'){
      // const nextIndex = i+1;
      // const _2ndChar = xmlData[nextIndex];
      if( xmlData[i+1] === '/') {//Closing Tag
        const closeIndex = findClosingIndex(xmlData, ">", i, "Closing Tag is not closed.")
        let tagName = xmlData.substring(i+2,closeIndex).trim();

        if(this.options.removeNSPrefix){
          const colonIndex = tagName.indexOf(":");
          if(colonIndex !== -1){
            tagName = tagName.substr(colonIndex+1);
          }
        }

        if(this.options.transformTagName) {
          tagName = this.options.transformTagName(tagName);
        }

        if(currentNode){
          textData = this.saveTextToParentTag(textData, currentNode, jPath);
        }

        //check if last tag of nested tag was unpaired tag
        const lastTagName = jPath.substring(jPath.lastIndexOf(".")+1);
        if(tagName && this.options.unpairedTags.indexOf(tagName) !== -1 ){
          throw new Error(`Unpaired tag can not be used as closing tag: </${tagName}>`);
        }
        let propIndex = 0
        if(lastTagName && this.options.unpairedTags.indexOf(lastTagName) !== -1 ){
          propIndex = jPath.lastIndexOf('.', jPath.lastIndexOf('.')-1)
          this.tagsNodeStack.pop();
        }else{
          propIndex = jPath.lastIndexOf(".");
        }
        jPath = jPath.substring(0, propIndex);

        currentNode = this.tagsNodeStack.pop();//avoid recursion, set the parent tag scope
        textData = "";
        i = closeIndex;
      } else if( xmlData[i+1] === '?') {

        let tagData = readTagExp(xmlData,i, false, "?>");
        if(!tagData) throw new Error("Pi Tag is not closed.");

        textData = this.saveTextToParentTag(textData, currentNode, jPath);
        if( (this.options.ignoreDeclaration && tagData.tagName === "?xml") || this.options.ignorePiTags){

        }else{
  
          const childNode = new xmlNode(tagData.tagName);
          childNode.add(this.options.textNodeName, "");
          
          if(tagData.tagName !== tagData.tagExp && tagData.attrExpPresent){
            childNode[":@"] = this.buildAttributesMap(tagData.tagExp, jPath, tagData.tagName);
          }
          this.addChild(currentNode, childNode, jPath)

        }


        i = tagData.closeIndex + 1;
      } else if(xmlData.substr(i + 1, 3) === '!--') {
        const endIndex = findClosingIndex(xmlData, "-->", i+4, "Comment is not closed.")
        if(this.options.commentPropName){
          const comment = xmlData.substring(i + 4, endIndex - 2);

          textData = this.saveTextToParentTag(textData, currentNode, jPath);

          currentNode.add(this.options.commentPropName, [ { [this.options.textNodeName] : comment } ]);
        }
        i = endIndex;
      } else if( xmlData.substr(i + 1, 2) === '!D') {
        const result = readDocType(xmlData, i);
        this.docTypeEntities = result.entities;
        i = result.i;
      }else if(xmlData.substr(i + 1, 2) === '![') {
        const closeIndex = findClosingIndex(xmlData, "]]>", i, "CDATA is not closed.") - 2;
        const tagExp = xmlData.substring(i + 9,closeIndex);

        textData = this.saveTextToParentTag(textData, currentNode, jPath);

        let val = this.parseTextData(tagExp, currentNode.tagname, jPath, true, false, true, true);
        if(val == undefined) val = "";

        //cdata should be set even if it is 0 length string
        if(this.options.cdataPropName){
          currentNode.add(this.options.cdataPropName, [ { [this.options.textNodeName] : tagExp } ]);
        }else{
          currentNode.add(this.options.textNodeName, val);
        }
        
        i = closeIndex + 2;
      }else {//Opening tag
        let result = readTagExp(xmlData,i, this.options.removeNSPrefix);
        let tagName= result.tagName;
        const rawTagName = result.rawTagName;
        let tagExp = result.tagExp;
        let attrExpPresent = result.attrExpPresent;
        let closeIndex = result.closeIndex;

        if (this.options.transformTagName) {
          tagName = this.options.transformTagName(tagName);
        }
        
        //save text as child node
        if (currentNode && textData) {
          if(currentNode.tagname !== '!xml'){
            //when nested tag is found
            textData = this.saveTextToParentTag(textData, currentNode, jPath, false);
          }
        }

        //check if last tag was unpaired tag
        const lastTag = currentNode;
        if(lastTag && this.options.unpairedTags.indexOf(lastTag.tagname) !== -1 ){
          currentNode = this.tagsNodeStack.pop();
          jPath = jPath.substring(0, jPath.lastIndexOf("."));
        }
        if(tagName !== xmlObj.tagname){
          jPath += jPath ? "." + tagName : tagName;
        }
        if (this.isItStopNode(this.options.stopNodes, jPath, tagName)) {
          let tagContent = "";
          //self-closing tag
          if(tagExp.length > 0 && tagExp.lastIndexOf("/") === tagExp.length - 1){
            if(tagName[tagName.length - 1] === "/"){ //remove trailing '/'
              tagName = tagName.substr(0, tagName.length - 1);
              jPath = jPath.substr(0, jPath.length - 1);
              tagExp = tagName;
            }else{
              tagExp = tagExp.substr(0, tagExp.length - 1);
            }
            i = result.closeIndex;
          }
          //unpaired tag
          else if(this.options.unpairedTags.indexOf(tagName) !== -1){
            
            i = result.closeIndex;
          }
          //normal tag
          else{
            //read until closing tag is found
            const result = this.readStopNodeData(xmlData, rawTagName, closeIndex + 1);
            if(!result) throw new Error(`Unexpected end of ${rawTagName}`);
            i = result.i;
            tagContent = result.tagContent;
          }

          const childNode = new xmlNode(tagName);
          if(tagName !== tagExp && attrExpPresent){
            childNode[":@"] = this.buildAttributesMap(tagExp, jPath, tagName);
          }
          if(tagContent) {
            tagContent = this.parseTextData(tagContent, tagName, jPath, true, attrExpPresent, true, true);
          }
          
          jPath = jPath.substr(0, jPath.lastIndexOf("."));
          childNode.add(this.options.textNodeName, tagContent);
          
          this.addChild(currentNode, childNode, jPath)
        }else{
  //selfClosing tag
          if(tagExp.length > 0 && tagExp.lastIndexOf("/") === tagExp.length - 1){
            if(tagName[tagName.length - 1] === "/"){ //remove trailing '/'
              tagName = tagName.substr(0, tagName.length - 1);
              jPath = jPath.substr(0, jPath.length - 1);
              tagExp = tagName;
            }else{
              tagExp = tagExp.substr(0, tagExp.length - 1);
            }
            
            if(this.options.transformTagName) {
              tagName = this.options.transformTagName(tagName);
            }

            const childNode = new xmlNode(tagName);
            if(tagName !== tagExp && attrExpPresent){
              childNode[":@"] = this.buildAttributesMap(tagExp, jPath, tagName);
            }
            this.addChild(currentNode, childNode, jPath)
            jPath = jPath.substr(0, jPath.lastIndexOf("."));
          }
    //opening tag
          else{
            const childNode = new xmlNode( tagName);
            this.tagsNodeStack.push(currentNode);
            
            if(tagName !== tagExp && attrExpPresent){
              childNode[":@"] = this.buildAttributesMap(tagExp, jPath, tagName);
            }
            this.addChild(currentNode, childNode, jPath)
            currentNode = childNode;
          }
          textData = "";
          i = closeIndex;
        }
      }
    }else{
      textData += xmlData[i];
    }
  }
  return xmlObj.child;
}

function addChild(currentNode, childNode, jPath){
  const result = this.options.updateTag(childNode.tagname, jPath, childNode[":@"])
  if(result === false){
  }else if(typeof result === "string"){
    childNode.tagname = result
    currentNode.addChild(childNode);
  }else{
    currentNode.addChild(childNode);
  }
}

const replaceEntitiesValue = function(val){

  if(this.options.processEntities){
    for(let entityName in this.docTypeEntities){
      const entity = this.docTypeEntities[entityName];
      val = val.replace( entity.regx, entity.val);
    }
    for(let entityName in this.lastEntities){
      const entity = this.lastEntities[entityName];
      val = val.replace( entity.regex, entity.val);
    }
    if(this.options.htmlEntities){
      for(let entityName in this.htmlEntities){
        const entity = this.htmlEntities[entityName];
        val = val.replace( entity.regex, entity.val);
      }
    }
    val = val.replace( this.ampEntity.regex, this.ampEntity.val);
  }
  return val;
}
function saveTextToParentTag(textData, currentNode, jPath, isLeafNode) {
  if (textData) { //store previously collected data as textNode
    if(isLeafNode === undefined) isLeafNode = Object.keys(currentNode.child).length === 0
    
    textData = this.parseTextData(textData,
      currentNode.tagname,
      jPath,
      false,
      currentNode[":@"] ? Object.keys(currentNode[":@"]).length !== 0 : false,
      isLeafNode);

    if (textData !== undefined && textData !== "")
      currentNode.add(this.options.textNodeName, textData);
    textData = "";
  }
  return textData;
}

//TODO: use jPath to simplify the logic
/**
 * 
 * @param {string[]} stopNodes 
 * @param {string} jPath
 * @param {string} currentTagName 
 */
function isItStopNode(stopNodes, jPath, currentTagName){
  const allNodesExp = "*." + currentTagName;
  for (const stopNodePath in stopNodes) {
    const stopNodeExp = stopNodes[stopNodePath];
    if( allNodesExp === stopNodeExp || jPath === stopNodeExp  ) return true;
  }
  return false;
}

/**
 * Returns the tag Expression and where it is ending handling single-double quotes situation
 * @param {string} xmlData 
 * @param {number} i starting index
 * @returns 
 */
function tagExpWithClosingIndex(xmlData, i, closingChar = ">"){
  let attrBoundary;
  let tagExp = "";
  for (let index = i; index < xmlData.length; index++) {
    let ch = xmlData[index];
    if (attrBoundary) {
        if (ch === attrBoundary) attrBoundary = "";//reset
    } else if (ch === '"' || ch === "'") {
        attrBoundary = ch;
    } else if (ch === closingChar[0]) {
      if(closingChar[1]){
        if(xmlData[index + 1] === closingChar[1]){
          return {
            data: tagExp,
            index: index
          }
        }
      }else{
        return {
          data: tagExp,
          index: index
        }
      }
    } else if (ch === '\t') {
      ch = " "
    }
    tagExp += ch;
  }
}

function findClosingIndex(xmlData, str, i, errMsg){
  const closingIndex = xmlData.indexOf(str, i);
  if(closingIndex === -1){
    throw new Error(errMsg)
  }else{
    return closingIndex + str.length - 1;
  }
}

function readTagExp(xmlData,i, removeNSPrefix, closingChar = ">"){
  const result = tagExpWithClosingIndex(xmlData, i+1, closingChar);
  if(!result) return;
  let tagExp = result.data;
  const closeIndex = result.index;
  const separatorIndex = tagExp.search(/\s/);
  let tagName = tagExp;
  let attrExpPresent = true;
  if(separatorIndex !== -1){//separate tag name and attributes expression
    tagName = tagExp.substring(0, separatorIndex);
    tagExp = tagExp.substring(separatorIndex + 1).trimStart();
  }

  const rawTagName = tagName;
  if(removeNSPrefix){
    const colonIndex = tagName.indexOf(":");
    if(colonIndex !== -1){
      tagName = tagName.substr(colonIndex+1);
      attrExpPresent = tagName !== result.data.substr(colonIndex + 1);
    }
  }

  return {
    tagName: tagName,
    tagExp: tagExp,
    closeIndex: closeIndex,
    attrExpPresent: attrExpPresent,
    rawTagName: rawTagName,
  }
}
/**
 * find paired tag for a stop node
 * @param {string} xmlData 
 * @param {string} tagName 
 * @param {number} i 
 */
function readStopNodeData(xmlData, tagName, i){
  const startIndex = i;
  // Starting at 1 since we already have an open tag
  let openTagCount = 1;

  for (; i < xmlData.length; i++) {
    if( xmlData[i] === "<"){ 
      if (xmlData[i+1] === "/") {//close tag
          const closeIndex = findClosingIndex(xmlData, ">", i, `${tagName} is not closed`);
          let closeTagName = xmlData.substring(i+2,closeIndex).trim();
          if(closeTagName === tagName){
            openTagCount--;
            if (openTagCount === 0) {
              return {
                tagContent: xmlData.substring(startIndex, i),
                i : closeIndex
              }
            }
          }
          i=closeIndex;
        } else if(xmlData[i+1] === '?') { 
          const closeIndex = findClosingIndex(xmlData, "?>", i+1, "StopNode is not closed.")
          i=closeIndex;
        } else if(xmlData.substr(i + 1, 3) === '!--') { 
          const closeIndex = findClosingIndex(xmlData, "-->", i+3, "StopNode is not closed.")
          i=closeIndex;
        } else if(xmlData.substr(i + 1, 2) === '![') { 
          const closeIndex = findClosingIndex(xmlData, "]]>", i, "StopNode is not closed.") - 2;
          i=closeIndex;
        } else {
          const tagData = readTagExp(xmlData, i, '>')

          if (tagData) {
            const openTagName = tagData && tagData.tagName;
            if (openTagName === tagName && tagData.tagExp[tagData.tagExp.length-1] !== "/") {
              openTagCount++;
            }
            i=tagData.closeIndex;
          }
        }
      }
  }//end for loop
}

function parseValue(val, shouldParse, options) {
  if (shouldParse && typeof val === 'string') {
    //console.log(options)
    const newval = val.trim();
    if(newval === 'true' ) return true;
    else if(newval === 'false' ) return false;
    else return toNumber(val, options);
  } else {
    if (util.isExist(val)) {
      return val;
    } else {
      return '';
    }
  }
}


module.exports = OrderedObjParser;


/***/ }),

/***/ 2380:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

const { buildOptions} = __nccwpck_require__(6993);
const OrderedObjParser = __nccwpck_require__(5832);
const { prettify} = __nccwpck_require__(2882);
const validator = __nccwpck_require__(1739);

class XMLParser{
    
    constructor(options){
        this.externalEntities = {};
        this.options = buildOptions(options);
        
    }
    /**
     * Parse XML dats to JS object 
     * @param {string|Buffer} xmlData 
     * @param {boolean|Object} validationOption 
     */
    parse(xmlData,validationOption){
        if(typeof xmlData === "string"){
        }else if( xmlData.toString){
            xmlData = xmlData.toString();
        }else{
            throw new Error("XML data is accepted in String or Bytes[] form.")
        }
        if( validationOption){
            if(validationOption === true) validationOption = {}; //validate with default options
            
            const result = validator.validate(xmlData, validationOption);
            if (result !== true) {
              throw Error( `${result.err.msg}:${result.err.line}:${result.err.col}` )
            }
          }
        const orderedObjParser = new OrderedObjParser(this.options);
        orderedObjParser.addExternalEntities(this.externalEntities);
        const orderedResult = orderedObjParser.parseXml(xmlData);
        if(this.options.preserveOrder || orderedResult === undefined) return orderedResult;
        else return prettify(orderedResult, this.options);
    }

    /**
     * Add Entity which is not by default supported by this library
     * @param {string} key 
     * @param {string} value 
     */
    addEntity(key, value){
        if(value.indexOf("&") !== -1){
            throw new Error("Entity value can't have '&'")
        }else if(key.indexOf("&") !== -1 || key.indexOf(";") !== -1){
            throw new Error("An entity must be set without '&' and ';'. Eg. use '#xD' for '&#xD;'")
        }else if(value === "&"){
            throw new Error("An entity with value '&' is not permitted");
        }else{
            this.externalEntities[key] = value;
        }
    }
}

module.exports = XMLParser;

/***/ }),

/***/ 2882:
/***/ ((__unused_webpack_module, exports) => {

"use strict";


/**
 * 
 * @param {array} node 
 * @param {any} options 
 * @returns 
 */
function prettify(node, options){
  return compress( node, options);
}

/**
 * 
 * @param {array} arr 
 * @param {object} options 
 * @param {string} jPath 
 * @returns object
 */
function compress(arr, options, jPath){
  let text;
  const compressedObj = {};
  for (let i = 0; i < arr.length; i++) {
    const tagObj = arr[i];
    const property = propName(tagObj);
    let newJpath = "";
    if(jPath === undefined) newJpath = property;
    else newJpath = jPath + "." + property;

    if(property === options.textNodeName){
      if(text === undefined) text = tagObj[property];
      else text += "" + tagObj[property];
    }else if(property === undefined){
      continue;
    }else if(tagObj[property]){
      
      let val = compress(tagObj[property], options, newJpath);
      const isLeaf = isLeafTag(val, options);

      if(tagObj[":@"]){
        assignAttributes( val, tagObj[":@"], newJpath, options);
      }else if(Object.keys(val).length === 1 && val[options.textNodeName] !== undefined && !options.alwaysCreateTextNode){
        val = val[options.textNodeName];
      }else if(Object.keys(val).length === 0){
        if(options.alwaysCreateTextNode) val[options.textNodeName] = "";
        else val = "";
      }

      if(compressedObj[property] !== undefined && compressedObj.hasOwnProperty(property)) {
        if(!Array.isArray(compressedObj[property])) {
            compressedObj[property] = [ compressedObj[property] ];
        }
        compressedObj[property].push(val);
      }else{
        //TODO: if a node is not an array, then check if it should be an array
        //also determine if it is a leaf node
        if (options.isArray(property, newJpath, isLeaf )) {
          compressedObj[property] = [val];
        }else{
          compressedObj[property] = val;
        }
      }
    }
    
  }
  // if(text && text.length > 0) compressedObj[options.textNodeName] = text;
  if(typeof text === "string"){
    if(text.length > 0) compressedObj[options.textNodeName] = text;
  }else if(text !== undefined) compressedObj[options.textNodeName] = text;
  return compressedObj;
}

function propName(obj){
  const keys = Object.keys(obj);
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    if(key !== ":@") return key;
  }
}

function assignAttributes(obj, attrMap, jpath, options){
  if (attrMap) {
    const keys = Object.keys(attrMap);
    const len = keys.length; //don't make it inline
    for (let i = 0; i < len; i++) {
      const atrrName = keys[i];
      if (options.isArray(atrrName, jpath + "." + atrrName, true, true)) {
        obj[atrrName] = [ attrMap[atrrName] ];
      } else {
        obj[atrrName] = attrMap[atrrName];
      }
    }
  }
}

function isLeafTag(obj, options){
  const { textNodeName } = options;
  const propCount = Object.keys(obj).length;
  
  if (propCount === 0) {
    return true;
  }

  if (
    propCount === 1 &&
    (obj[textNodeName] || typeof obj[textNodeName] === "boolean" || obj[textNodeName] === 0)
  ) {
    return true;
  }

  return false;
}
exports.prettify = prettify;


/***/ }),

/***/ 7462:
/***/ ((module) => {

"use strict";


class XmlNode{
  constructor(tagname) {
    this.tagname = tagname;
    this.child = []; //nested tags, text, cdata, comments in order
    this[":@"] = {}; //attributes map
  }
  add(key,val){
    // this.child.push( {name : key, val: val, isCdata: isCdata });
    if(key === "__proto__") key = "#__proto__";
    this.child.push( {[key]: val });
  }
  addChild(node) {
    if(node.tagname === "__proto__") node.tagname = "#__proto__";
    if(node[":@"] && Object.keys(node[":@"]).length > 0){
      this.child.push( { [node.tagname]: node.child, [":@"]: node[":@"] });
    }else{
      this.child.push( { [node.tagname]: node.child });
    }
  };
};


module.exports = XmlNode;

/***/ }),

/***/ 4526:
/***/ ((module) => {

const hexRegex = /^[-+]?0x[a-fA-F0-9]+$/;
const numRegex = /^([\-\+])?(0*)(\.[0-9]+([eE]\-?[0-9]+)?|[0-9]+(\.[0-9]+([eE]\-?[0-9]+)?)?)$/;
// const octRegex = /0x[a-z0-9]+/;
// const binRegex = /0x[a-z0-9]+/;


//polyfill
if (!Number.parseInt && window.parseInt) {
    Number.parseInt = window.parseInt;
}
if (!Number.parseFloat && window.parseFloat) {
    Number.parseFloat = window.parseFloat;
}

  
const consider = {
    hex :  true,
    leadingZeros: true,
    decimalPoint: "\.",
    eNotation: true
    //skipLike: /regex/
};

function toNumber(str, options = {}){
    // const options = Object.assign({}, consider);
    // if(opt.leadingZeros === false){
    //     options.leadingZeros = false;
    // }else if(opt.hex === false){
    //     options.hex = false;
    // }

    options = Object.assign({}, consider, options );
    if(!str || typeof str !== "string" ) return str;
    
    let trimmedStr  = str.trim();
    // if(trimmedStr === "0.0") return 0;
    // else if(trimmedStr === "+0.0") return 0;
    // else if(trimmedStr === "-0.0") return -0;

    if(options.skipLike !== undefined && options.skipLike.test(trimmedStr)) return str;
    else if (options.hex && hexRegex.test(trimmedStr)) {
        return Number.parseInt(trimmedStr, 16);
    // } else if (options.parseOct && octRegex.test(str)) {
    //     return Number.parseInt(val, 8);
    // }else if (options.parseBin && binRegex.test(str)) {
    //     return Number.parseInt(val, 2);
    }else{
        //separate negative sign, leading zeros, and rest number
        const match = numRegex.exec(trimmedStr);
        if(match){
            const sign = match[1];
            const leadingZeros = match[2];
            let numTrimmedByZeros = trimZeros(match[3]); //complete num without leading zeros
            //trim ending zeros for floating number
            
            const eNotation = match[4] || match[6];
            if(!options.leadingZeros && leadingZeros.length > 0 && sign && trimmedStr[2] !== ".") return str; //-0123
            else if(!options.leadingZeros && leadingZeros.length > 0 && !sign && trimmedStr[1] !== ".") return str; //0123
            else{//no leading zeros or leading zeros are allowed
                const num = Number(trimmedStr);
                const numStr = "" + num;
                if(numStr.search(/[eE]/) !== -1){ //given number is long and parsed to eNotation
                    if(options.eNotation) return num;
                    else return str;
                }else if(eNotation){ //given number has enotation
                    if(options.eNotation) return num;
                    else return str;
                }else if(trimmedStr.indexOf(".") !== -1){ //floating number
                    // const decimalPart = match[5].substr(1);
                    // const intPart = trimmedStr.substr(0,trimmedStr.indexOf("."));

                    
                    // const p = numStr.indexOf(".");
                    // const givenIntPart = numStr.substr(0,p);
                    // const givenDecPart = numStr.substr(p+1);
                    if(numStr === "0" && (numTrimmedByZeros === "") ) return num; //0.0
                    else if(numStr === numTrimmedByZeros) return num; //0.456. 0.79000
                    else if( sign && numStr === "-"+numTrimmedByZeros) return num;
                    else return str;
                }
                
                if(leadingZeros){
                    // if(numTrimmedByZeros === numStr){
                    //     if(options.leadingZeros) return num;
                    //     else return str;
                    // }else return str;
                    if(numTrimmedByZeros === numStr) return num;
                    else if(sign+numTrimmedByZeros === numStr) return num;
                    else return str;
                }

                if(trimmedStr === numStr) return num;
                else if(trimmedStr === sign+numStr) return num;
                // else{
                //     //number with +/- sign
                //     trimmedStr.test(/[-+][0-9]);

                // }
                return str;
            }
            // else if(!eNotation && trimmedStr && trimmedStr !== Number(trimmedStr) ) return str;
            
        }else{ //non-numeric string
            return str;
        }
    }
}

/**
 * 
 * @param {string} numStr without leading zeros
 * @returns 
 */
function trimZeros(numStr){
    if(numStr && numStr.indexOf(".") !== -1){//float
        numStr = numStr.replace(/0+$/, ""); //remove ending zeros
        if(numStr === ".")  numStr = "0";
        else if(numStr[0] === ".")  numStr = "0"+numStr;
        else if(numStr[numStr.length-1] === ".")  numStr = numStr.substr(0,numStr.length-1);
        return numStr;
    }
    return numStr;
}
module.exports = toNumber


/***/ }),

/***/ 4351:
/***/ ((module) => {

/******************************************************************************
Copyright (c) Microsoft Corporation.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
***************************************************************************** */
/* global global, define, Symbol, Reflect, Promise, SuppressedError */
var __extends;
var __assign;
var __rest;
var __decorate;
var __param;
var __esDecorate;
var __runInitializers;
var __propKey;
var __setFunctionName;
var __metadata;
var __awaiter;
var __generator;
var __exportStar;
var __values;
var __read;
var __spread;
var __spreadArrays;
var __spreadArray;
var __await;
var __asyncGenerator;
var __asyncDelegator;
var __asyncValues;
var __makeTemplateObject;
var __importStar;
var __importDefault;
var __classPrivateFieldGet;
var __classPrivateFieldSet;
var __classPrivateFieldIn;
var __createBinding;
var __addDisposableResource;
var __disposeResources;
(function (factory) {
    var root = typeof global === "object" ? global : typeof self === "object" ? self : typeof this === "object" ? this : {};
    if (typeof define === "function" && define.amd) {
        define("tslib", ["exports"], function (exports) { factory(createExporter(root, createExporter(exports))); });
    }
    else if ( true && typeof module.exports === "object") {
        factory(createExporter(root, createExporter(module.exports)));
    }
    else {
        factory(createExporter(root));
    }
    function createExporter(exports, previous) {
        if (exports !== root) {
            if (typeof Object.create === "function") {
                Object.defineProperty(exports, "__esModule", { value: true });
            }
            else {
                exports.__esModule = true;
            }
        }
        return function (id, v) { return exports[id] = previous ? previous(id, v) : v; };
    }
})
(function (exporter) {
    var extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (Object.prototype.hasOwnProperty.call(b, p)) d[p] = b[p]; };

    __extends = function (d, b) {
        if (typeof b !== "function" && b !== null)
            throw new TypeError("Class extends value " + String(b) + " is not a constructor or null");
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };

    __assign = Object.assign || function (t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p)) t[p] = s[p];
        }
        return t;
    };

    __rest = function (s, e) {
        var t = {};
        for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
            t[p] = s[p];
        if (s != null && typeof Object.getOwnPropertySymbols === "function")
            for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
                if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                    t[p[i]] = s[p[i]];
            }
        return t;
    };

    __decorate = function (decorators, target, key, desc) {
        var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
        if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
        else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
        return c > 3 && r && Object.defineProperty(target, key, r), r;
    };

    __param = function (paramIndex, decorator) {
        return function (target, key) { decorator(target, key, paramIndex); }
    };

    __esDecorate = function (ctor, descriptorIn, decorators, contextIn, initializers, extraInitializers) {
        function accept(f) { if (f !== void 0 && typeof f !== "function") throw new TypeError("Function expected"); return f; }
        var kind = contextIn.kind, key = kind === "getter" ? "get" : kind === "setter" ? "set" : "value";
        var target = !descriptorIn && ctor ? contextIn["static"] ? ctor : ctor.prototype : null;
        var descriptor = descriptorIn || (target ? Object.getOwnPropertyDescriptor(target, contextIn.name) : {});
        var _, done = false;
        for (var i = decorators.length - 1; i >= 0; i--) {
            var context = {};
            for (var p in contextIn) context[p] = p === "access" ? {} : contextIn[p];
            for (var p in contextIn.access) context.access[p] = contextIn.access[p];
            context.addInitializer = function (f) { if (done) throw new TypeError("Cannot add initializers after decoration has completed"); extraInitializers.push(accept(f || null)); };
            var result = (0, decorators[i])(kind === "accessor" ? { get: descriptor.get, set: descriptor.set } : descriptor[key], context);
            if (kind === "accessor") {
                if (result === void 0) continue;
                if (result === null || typeof result !== "object") throw new TypeError("Object expected");
                if (_ = accept(result.get)) descriptor.get = _;
                if (_ = accept(result.set)) descriptor.set = _;
                if (_ = accept(result.init)) initializers.unshift(_);
            }
            else if (_ = accept(result)) {
                if (kind === "field") initializers.unshift(_);
                else descriptor[key] = _;
            }
        }
        if (target) Object.defineProperty(target, contextIn.name, descriptor);
        done = true;
    };

    __runInitializers = function (thisArg, initializers, value) {
        var useValue = arguments.length > 2;
        for (var i = 0; i < initializers.length; i++) {
            value = useValue ? initializers[i].call(thisArg, value) : initializers[i].call(thisArg);
        }
        return useValue ? value : void 0;
    };

    __propKey = function (x) {
        return typeof x === "symbol" ? x : "".concat(x);
    };

    __setFunctionName = function (f, name, prefix) {
        if (typeof name === "symbol") name = name.description ? "[".concat(name.description, "]") : "";
        return Object.defineProperty(f, "name", { configurable: true, value: prefix ? "".concat(prefix, " ", name) : name });
    };

    __metadata = function (metadataKey, metadataValue) {
        if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(metadataKey, metadataValue);
    };

    __awaiter = function (thisArg, _arguments, P, generator) {
        function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
        return new (P || (P = Promise))(function (resolve, reject) {
            function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
            function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
            function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
            step((generator = generator.apply(thisArg, _arguments || [])).next());
        });
    };

    __generator = function (thisArg, body) {
        var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
        return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
        function verb(n) { return function (v) { return step([n, v]); }; }
        function step(op) {
            if (f) throw new TypeError("Generator is already executing.");
            while (g && (g = 0, op[0] && (_ = 0)), _) try {
                if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
                if (y = 0, t) op = [op[0] & 2, t.value];
                switch (op[0]) {
                    case 0: case 1: t = op; break;
                    case 4: _.label++; return { value: op[1], done: false };
                    case 5: _.label++; y = op[1]; op = [0]; continue;
                    case 7: op = _.ops.pop(); _.trys.pop(); continue;
                    default:
                        if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                        if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                        if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                        if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                        if (t[2]) _.ops.pop();
                        _.trys.pop(); continue;
                }
                op = body.call(thisArg, _);
            } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
            if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
        }
    };

    __exportStar = function(m, o) {
        for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(o, p)) __createBinding(o, m, p);
    };

    __createBinding = Object.create ? (function(o, m, k, k2) {
        if (k2 === undefined) k2 = k;
        var desc = Object.getOwnPropertyDescriptor(m, k);
        if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
            desc = { enumerable: true, get: function() { return m[k]; } };
        }
        Object.defineProperty(o, k2, desc);
    }) : (function(o, m, k, k2) {
        if (k2 === undefined) k2 = k;
        o[k2] = m[k];
    });

    __values = function (o) {
        var s = typeof Symbol === "function" && Symbol.iterator, m = s && o[s], i = 0;
        if (m) return m.call(o);
        if (o && typeof o.length === "number") return {
            next: function () {
                if (o && i >= o.length) o = void 0;
                return { value: o && o[i++], done: !o };
            }
        };
        throw new TypeError(s ? "Object is not iterable." : "Symbol.iterator is not defined.");
    };

    __read = function (o, n) {
        var m = typeof Symbol === "function" && o[Symbol.iterator];
        if (!m) return o;
        var i = m.call(o), r, ar = [], e;
        try {
            while ((n === void 0 || n-- > 0) && !(r = i.next()).done) ar.push(r.value);
        }
        catch (error) { e = { error: error }; }
        finally {
            try {
                if (r && !r.done && (m = i["return"])) m.call(i);
            }
            finally { if (e) throw e.error; }
        }
        return ar;
    };

    /** @deprecated */
    __spread = function () {
        for (var ar = [], i = 0; i < arguments.length; i++)
            ar = ar.concat(__read(arguments[i]));
        return ar;
    };

    /** @deprecated */
    __spreadArrays = function () {
        for (var s = 0, i = 0, il = arguments.length; i < il; i++) s += arguments[i].length;
        for (var r = Array(s), k = 0, i = 0; i < il; i++)
            for (var a = arguments[i], j = 0, jl = a.length; j < jl; j++, k++)
                r[k] = a[j];
        return r;
    };

    __spreadArray = function (to, from, pack) {
        if (pack || arguments.length === 2) for (var i = 0, l = from.length, ar; i < l; i++) {
            if (ar || !(i in from)) {
                if (!ar) ar = Array.prototype.slice.call(from, 0, i);
                ar[i] = from[i];
            }
        }
        return to.concat(ar || Array.prototype.slice.call(from));
    };

    __await = function (v) {
        return this instanceof __await ? (this.v = v, this) : new __await(v);
    };

    __asyncGenerator = function (thisArg, _arguments, generator) {
        if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
        var g = generator.apply(thisArg, _arguments || []), i, q = [];
        return i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i;
        function verb(n) { if (g[n]) i[n] = function (v) { return new Promise(function (a, b) { q.push([n, v, a, b]) > 1 || resume(n, v); }); }; }
        function resume(n, v) { try { step(g[n](v)); } catch (e) { settle(q[0][3], e); } }
        function step(r) { r.value instanceof __await ? Promise.resolve(r.value.v).then(fulfill, reject) : settle(q[0][2], r);  }
        function fulfill(value) { resume("next", value); }
        function reject(value) { resume("throw", value); }
        function settle(f, v) { if (f(v), q.shift(), q.length) resume(q[0][0], q[0][1]); }
    };

    __asyncDelegator = function (o) {
        var i, p;
        return i = {}, verb("next"), verb("throw", function (e) { throw e; }), verb("return"), i[Symbol.iterator] = function () { return this; }, i;
        function verb(n, f) { i[n] = o[n] ? function (v) { return (p = !p) ? { value: __await(o[n](v)), done: false } : f ? f(v) : v; } : f; }
    };

    __asyncValues = function (o) {
        if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
        var m = o[Symbol.asyncIterator], i;
        return m ? m.call(o) : (o = typeof __values === "function" ? __values(o) : o[Symbol.iterator](), i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i);
        function verb(n) { i[n] = o[n] && function (v) { return new Promise(function (resolve, reject) { v = o[n](v), settle(resolve, reject, v.done, v.value); }); }; }
        function settle(resolve, reject, d, v) { Promise.resolve(v).then(function(v) { resolve({ value: v, done: d }); }, reject); }
    };

    __makeTemplateObject = function (cooked, raw) {
        if (Object.defineProperty) { Object.defineProperty(cooked, "raw", { value: raw }); } else { cooked.raw = raw; }
        return cooked;
    };

    var __setModuleDefault = Object.create ? (function(o, v) {
        Object.defineProperty(o, "default", { enumerable: true, value: v });
    }) : function(o, v) {
        o["default"] = v;
    };

    __importStar = function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
        __setModuleDefault(result, mod);
        return result;
    };

    __importDefault = function (mod) {
        return (mod && mod.__esModule) ? mod : { "default": mod };
    };

    __classPrivateFieldGet = function (receiver, state, kind, f) {
        if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a getter");
        if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
        return kind === "m" ? f : kind === "a" ? f.call(receiver) : f ? f.value : state.get(receiver);
    };

    __classPrivateFieldSet = function (receiver, state, value, kind, f) {
        if (kind === "m") throw new TypeError("Private method is not writable");
        if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a setter");
        if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot write private member to an object whose class did not declare it");
        return (kind === "a" ? f.call(receiver, value) : f ? f.value = value : state.set(receiver, value)), value;
    };

    __classPrivateFieldIn = function (state, receiver) {
        if (receiver === null || (typeof receiver !== "object" && typeof receiver !== "function")) throw new TypeError("Cannot use 'in' operator on non-object");
        return typeof state === "function" ? receiver === state : state.has(receiver);
    };

    __addDisposableResource = function (env, value, async) {
        if (value !== null && value !== void 0) {
            if (typeof value !== "object" && typeof value !== "function") throw new TypeError("Object expected.");
            var dispose;
            if (async) {
                if (!Symbol.asyncDispose) throw new TypeError("Symbol.asyncDispose is not defined.");
                dispose = value[Symbol.asyncDispose];
            }
            if (dispose === void 0) {
                if (!Symbol.dispose) throw new TypeError("Symbol.dispose is not defined.");
                dispose = value[Symbol.dispose];
            }
            if (typeof dispose !== "function") throw new TypeError("Object not disposable.");
            env.stack.push({ value: value, dispose: dispose, async: async });
        }
        else if (async) {
            env.stack.push({ async: true });
        }
        return value;
    };

    var _SuppressedError = typeof SuppressedError === "function" ? SuppressedError : function (error, suppressed, message) {
        var e = new Error(message);
        return e.name = "SuppressedError", e.error = error, e.suppressed = suppressed, e;
    };

    __disposeResources = function (env) {
        function fail(e) {
            env.error = env.hasError ? new _SuppressedError(e, env.error, "An error was suppressed during disposal.") : e;
            env.hasError = true;
        }
        function next() {
            while (env.stack.length) {
                var rec = env.stack.pop();
                try {
                    var result = rec.dispose && rec.dispose.call(rec.value);
                    if (rec.async) return Promise.resolve(result).then(next, function(e) { fail(e); return next(); });
                }
                catch (e) {
                    fail(e);
                }
            }
            if (env.hasError) throw env.error;
        }
        return next();
    };

    exporter("__extends", __extends);
    exporter("__assign", __assign);
    exporter("__rest", __rest);
    exporter("__decorate", __decorate);
    exporter("__param", __param);
    exporter("__esDecorate", __esDecorate);
    exporter("__runInitializers", __runInitializers);
    exporter("__propKey", __propKey);
    exporter("__setFunctionName", __setFunctionName);
    exporter("__metadata", __metadata);
    exporter("__awaiter", __awaiter);
    exporter("__generator", __generator);
    exporter("__exportStar", __exportStar);
    exporter("__createBinding", __createBinding);
    exporter("__values", __values);
    exporter("__read", __read);
    exporter("__spread", __spread);
    exporter("__spreadArrays", __spreadArrays);
    exporter("__spreadArray", __spreadArray);
    exporter("__await", __await);
    exporter("__asyncGenerator", __asyncGenerator);
    exporter("__asyncDelegator", __asyncDelegator);
    exporter("__asyncValues", __asyncValues);
    exporter("__makeTemplateObject", __makeTemplateObject);
    exporter("__importStar", __importStar);
    exporter("__importDefault", __importDefault);
    exporter("__classPrivateFieldGet", __classPrivateFieldGet);
    exporter("__classPrivateFieldSet", __classPrivateFieldSet);
    exporter("__classPrivateFieldIn", __classPrivateFieldIn);
    exporter("__addDisposableResource", __addDisposableResource);
    exporter("__disposeResources", __disposeResources);
});


/***/ }),

/***/ 4294:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

module.exports = __nccwpck_require__(4219);


/***/ }),

/***/ 4219:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


var net = __nccwpck_require__(1808);
var tls = __nccwpck_require__(4404);
var http = __nccwpck_require__(3685);
var https = __nccwpck_require__(5687);
var events = __nccwpck_require__(2361);
var assert = __nccwpck_require__(9491);
var util = __nccwpck_require__(3837);


exports.httpOverHttp = httpOverHttp;
exports.httpsOverHttp = httpsOverHttp;
exports.httpOverHttps = httpOverHttps;
exports.httpsOverHttps = httpsOverHttps;


function httpOverHttp(options) {
  var agent = new TunnelingAgent(options);
  agent.request = http.request;
  return agent;
}

function httpsOverHttp(options) {
  var agent = new TunnelingAgent(options);
  agent.request = http.request;
  agent.createSocket = createSecureSocket;
  agent.defaultPort = 443;
  return agent;
}

function httpOverHttps(options) {
  var agent = new TunnelingAgent(options);
  agent.request = https.request;
  return agent;
}

function httpsOverHttps(options) {
  var agent = new TunnelingAgent(options);
  agent.request = https.request;
  agent.createSocket = createSecureSocket;
  agent.defaultPort = 443;
  return agent;
}


function TunnelingAgent(options) {
  var self = this;
  self.options = options || {};
  self.proxyOptions = self.options.proxy || {};
  self.maxSockets = self.options.maxSockets || http.Agent.defaultMaxSockets;
  self.requests = [];
  self.sockets = [];

  self.on('free', function onFree(socket, host, port, localAddress) {
    var options = toOptions(host, port, localAddress);
    for (var i = 0, len = self.requests.length; i < len; ++i) {
      var pending = self.requests[i];
      if (pending.host === options.host && pending.port === options.port) {
        // Detect the request to connect same origin server,
        // reuse the connection.
        self.requests.splice(i, 1);
        pending.request.onSocket(socket);
        return;
      }
    }
    socket.destroy();
    self.removeSocket(socket);
  });
}
util.inherits(TunnelingAgent, events.EventEmitter);

TunnelingAgent.prototype.addRequest = function addRequest(req, host, port, localAddress) {
  var self = this;
  var options = mergeOptions({request: req}, self.options, toOptions(host, port, localAddress));

  if (self.sockets.length >= this.maxSockets) {
    // We are over limit so we'll add it to the queue.
    self.requests.push(options);
    return;
  }

  // If we are under maxSockets create a new one.
  self.createSocket(options, function(socket) {
    socket.on('free', onFree);
    socket.on('close', onCloseOrRemove);
    socket.on('agentRemove', onCloseOrRemove);
    req.onSocket(socket);

    function onFree() {
      self.emit('free', socket, options);
    }

    function onCloseOrRemove(err) {
      self.removeSocket(socket);
      socket.removeListener('free', onFree);
      socket.removeListener('close', onCloseOrRemove);
      socket.removeListener('agentRemove', onCloseOrRemove);
    }
  });
};

TunnelingAgent.prototype.createSocket = function createSocket(options, cb) {
  var self = this;
  var placeholder = {};
  self.sockets.push(placeholder);

  var connectOptions = mergeOptions({}, self.proxyOptions, {
    method: 'CONNECT',
    path: options.host + ':' + options.port,
    agent: false,
    headers: {
      host: options.host + ':' + options.port
    }
  });
  if (options.localAddress) {
    connectOptions.localAddress = options.localAddress;
  }
  if (connectOptions.proxyAuth) {
    connectOptions.headers = connectOptions.headers || {};
    connectOptions.headers['Proxy-Authorization'] = 'Basic ' +
        new Buffer(connectOptions.proxyAuth).toString('base64');
  }

  debug('making CONNECT request');
  var connectReq = self.request(connectOptions);
  connectReq.useChunkedEncodingByDefault = false; // for v0.6
  connectReq.once('response', onResponse); // for v0.6
  connectReq.once('upgrade', onUpgrade);   // for v0.6
  connectReq.once('connect', onConnect);   // for v0.7 or later
  connectReq.once('error', onError);
  connectReq.end();

  function onResponse(res) {
    // Very hacky. This is necessary to avoid http-parser leaks.
    res.upgrade = true;
  }

  function onUpgrade(res, socket, head) {
    // Hacky.
    process.nextTick(function() {
      onConnect(res, socket, head);
    });
  }

  function onConnect(res, socket, head) {
    connectReq.removeAllListeners();
    socket.removeAllListeners();

    if (res.statusCode !== 200) {
      debug('tunneling socket could not be established, statusCode=%d',
        res.statusCode);
      socket.destroy();
      var error = new Error('tunneling socket could not be established, ' +
        'statusCode=' + res.statusCode);
      error.code = 'ECONNRESET';
      options.request.emit('error', error);
      self.removeSocket(placeholder);
      return;
    }
    if (head.length > 0) {
      debug('got illegal response body from proxy');
      socket.destroy();
      var error = new Error('got illegal response body from proxy');
      error.code = 'ECONNRESET';
      options.request.emit('error', error);
      self.removeSocket(placeholder);
      return;
    }
    debug('tunneling connection has established');
    self.sockets[self.sockets.indexOf(placeholder)] = socket;
    return cb(socket);
  }

  function onError(cause) {
    connectReq.removeAllListeners();

    debug('tunneling socket could not be established, cause=%s\n',
          cause.message, cause.stack);
    var error = new Error('tunneling socket could not be established, ' +
                          'cause=' + cause.message);
    error.code = 'ECONNRESET';
    options.request.emit('error', error);
    self.removeSocket(placeholder);
  }
};

TunnelingAgent.prototype.removeSocket = function removeSocket(socket) {
  var pos = this.sockets.indexOf(socket)
  if (pos === -1) {
    return;
  }
  this.sockets.splice(pos, 1);

  var pending = this.requests.shift();
  if (pending) {
    // If we have pending requests and a socket gets closed a new one
    // needs to be created to take over in the pool for the one that closed.
    this.createSocket(pending, function(socket) {
      pending.request.onSocket(socket);
    });
  }
};

function createSecureSocket(options, cb) {
  var self = this;
  TunnelingAgent.prototype.createSocket.call(self, options, function(socket) {
    var hostHeader = options.request.getHeader('host');
    var tlsOptions = mergeOptions({}, self.options, {
      socket: socket,
      servername: hostHeader ? hostHeader.replace(/:.*$/, '') : options.host
    });

    // 0 is dummy port for v0.6
    var secureSocket = tls.connect(0, tlsOptions);
    self.sockets[self.sockets.indexOf(socket)] = secureSocket;
    cb(secureSocket);
  });
}


function toOptions(host, port, localAddress) {
  if (typeof host === 'string') { // since v0.10
    return {
      host: host,
      port: port,
      localAddress: localAddress
    };
  }
  return host; // for v0.11 or later
}

function mergeOptions(target) {
  for (var i = 1, len = arguments.length; i < len; ++i) {
    var overrides = arguments[i];
    if (typeof overrides === 'object') {
      var keys = Object.keys(overrides);
      for (var j = 0, keyLen = keys.length; j < keyLen; ++j) {
        var k = keys[j];
        if (overrides[k] !== undefined) {
          target[k] = overrides[k];
        }
      }
    }
  }
  return target;
}


var debug;
if (process.env.NODE_DEBUG && /\btunnel\b/.test(process.env.NODE_DEBUG)) {
  debug = function() {
    var args = Array.prototype.slice.call(arguments);
    if (typeof args[0] === 'string') {
      args[0] = 'TUNNEL: ' + args[0];
    } else {
      args.unshift('TUNNEL:');
    }
    console.error.apply(console, args);
  }
} else {
  debug = function() {};
}
exports.debug = debug; // for test


/***/ }),

/***/ 5840:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
Object.defineProperty(exports, "v1", ({
  enumerable: true,
  get: function () {
    return _v.default;
  }
}));
Object.defineProperty(exports, "v3", ({
  enumerable: true,
  get: function () {
    return _v2.default;
  }
}));
Object.defineProperty(exports, "v4", ({
  enumerable: true,
  get: function () {
    return _v3.default;
  }
}));
Object.defineProperty(exports, "v5", ({
  enumerable: true,
  get: function () {
    return _v4.default;
  }
}));
Object.defineProperty(exports, "NIL", ({
  enumerable: true,
  get: function () {
    return _nil.default;
  }
}));
Object.defineProperty(exports, "version", ({
  enumerable: true,
  get: function () {
    return _version.default;
  }
}));
Object.defineProperty(exports, "validate", ({
  enumerable: true,
  get: function () {
    return _validate.default;
  }
}));
Object.defineProperty(exports, "stringify", ({
  enumerable: true,
  get: function () {
    return _stringify.default;
  }
}));
Object.defineProperty(exports, "parse", ({
  enumerable: true,
  get: function () {
    return _parse.default;
  }
}));

var _v = _interopRequireDefault(__nccwpck_require__(8628));

var _v2 = _interopRequireDefault(__nccwpck_require__(6409));

var _v3 = _interopRequireDefault(__nccwpck_require__(5122));

var _v4 = _interopRequireDefault(__nccwpck_require__(9120));

var _nil = _interopRequireDefault(__nccwpck_require__(5332));

var _version = _interopRequireDefault(__nccwpck_require__(1595));

var _validate = _interopRequireDefault(__nccwpck_require__(6900));

var _stringify = _interopRequireDefault(__nccwpck_require__(8950));

var _parse = _interopRequireDefault(__nccwpck_require__(2746));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/***/ }),

/***/ 4569:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _crypto = _interopRequireDefault(__nccwpck_require__(6113));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function md5(bytes) {
  if (Array.isArray(bytes)) {
    bytes = Buffer.from(bytes);
  } else if (typeof bytes === 'string') {
    bytes = Buffer.from(bytes, 'utf8');
  }

  return _crypto.default.createHash('md5').update(bytes).digest();
}

var _default = md5;
exports["default"] = _default;

/***/ }),

/***/ 5332:
/***/ ((__unused_webpack_module, exports) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;
var _default = '00000000-0000-0000-0000-000000000000';
exports["default"] = _default;

/***/ }),

/***/ 2746:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _validate = _interopRequireDefault(__nccwpck_require__(6900));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function parse(uuid) {
  if (!(0, _validate.default)(uuid)) {
    throw TypeError('Invalid UUID');
  }

  let v;
  const arr = new Uint8Array(16); // Parse ########-....-....-....-............

  arr[0] = (v = parseInt(uuid.slice(0, 8), 16)) >>> 24;
  arr[1] = v >>> 16 & 0xff;
  arr[2] = v >>> 8 & 0xff;
  arr[3] = v & 0xff; // Parse ........-####-....-....-............

  arr[4] = (v = parseInt(uuid.slice(9, 13), 16)) >>> 8;
  arr[5] = v & 0xff; // Parse ........-....-####-....-............

  arr[6] = (v = parseInt(uuid.slice(14, 18), 16)) >>> 8;
  arr[7] = v & 0xff; // Parse ........-....-....-####-............

  arr[8] = (v = parseInt(uuid.slice(19, 23), 16)) >>> 8;
  arr[9] = v & 0xff; // Parse ........-....-....-....-############
  // (Use "/" to avoid 32-bit truncation when bit-shifting high-order bytes)

  arr[10] = (v = parseInt(uuid.slice(24, 36), 16)) / 0x10000000000 & 0xff;
  arr[11] = v / 0x100000000 & 0xff;
  arr[12] = v >>> 24 & 0xff;
  arr[13] = v >>> 16 & 0xff;
  arr[14] = v >>> 8 & 0xff;
  arr[15] = v & 0xff;
  return arr;
}

var _default = parse;
exports["default"] = _default;

/***/ }),

/***/ 814:
/***/ ((__unused_webpack_module, exports) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;
var _default = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000)$/i;
exports["default"] = _default;

/***/ }),

/***/ 807:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = rng;

var _crypto = _interopRequireDefault(__nccwpck_require__(6113));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const rnds8Pool = new Uint8Array(256); // # of random values to pre-allocate

let poolPtr = rnds8Pool.length;

function rng() {
  if (poolPtr > rnds8Pool.length - 16) {
    _crypto.default.randomFillSync(rnds8Pool);

    poolPtr = 0;
  }

  return rnds8Pool.slice(poolPtr, poolPtr += 16);
}

/***/ }),

/***/ 5274:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _crypto = _interopRequireDefault(__nccwpck_require__(6113));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function sha1(bytes) {
  if (Array.isArray(bytes)) {
    bytes = Buffer.from(bytes);
  } else if (typeof bytes === 'string') {
    bytes = Buffer.from(bytes, 'utf8');
  }

  return _crypto.default.createHash('sha1').update(bytes).digest();
}

var _default = sha1;
exports["default"] = _default;

/***/ }),

/***/ 8950:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _validate = _interopRequireDefault(__nccwpck_require__(6900));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * Convert array of 16 byte values to UUID string format of the form:
 * XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
 */
const byteToHex = [];

for (let i = 0; i < 256; ++i) {
  byteToHex.push((i + 0x100).toString(16).substr(1));
}

function stringify(arr, offset = 0) {
  // Note: Be careful editing this code!  It's been tuned for performance
  // and works in ways you may not expect. See https://github.com/uuidjs/uuid/pull/434
  const uuid = (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + '-' + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + '-' + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + '-' + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + '-' + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase(); // Consistency check for valid UUID.  If this throws, it's likely due to one
  // of the following:
  // - One or more input array values don't map to a hex octet (leading to
  // "undefined" in the uuid)
  // - Invalid input values for the RFC `version` or `variant` fields

  if (!(0, _validate.default)(uuid)) {
    throw TypeError('Stringified UUID is invalid');
  }

  return uuid;
}

var _default = stringify;
exports["default"] = _default;

/***/ }),

/***/ 8628:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _rng = _interopRequireDefault(__nccwpck_require__(807));

var _stringify = _interopRequireDefault(__nccwpck_require__(8950));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

// **`v1()` - Generate time-based UUID**
//
// Inspired by https://github.com/LiosK/UUID.js
// and http://docs.python.org/library/uuid.html
let _nodeId;

let _clockseq; // Previous uuid creation time


let _lastMSecs = 0;
let _lastNSecs = 0; // See https://github.com/uuidjs/uuid for API details

function v1(options, buf, offset) {
  let i = buf && offset || 0;
  const b = buf || new Array(16);
  options = options || {};
  let node = options.node || _nodeId;
  let clockseq = options.clockseq !== undefined ? options.clockseq : _clockseq; // node and clockseq need to be initialized to random values if they're not
  // specified.  We do this lazily to minimize issues related to insufficient
  // system entropy.  See #189

  if (node == null || clockseq == null) {
    const seedBytes = options.random || (options.rng || _rng.default)();

    if (node == null) {
      // Per 4.5, create and 48-bit node id, (47 random bits + multicast bit = 1)
      node = _nodeId = [seedBytes[0] | 0x01, seedBytes[1], seedBytes[2], seedBytes[3], seedBytes[4], seedBytes[5]];
    }

    if (clockseq == null) {
      // Per 4.2.2, randomize (14 bit) clockseq
      clockseq = _clockseq = (seedBytes[6] << 8 | seedBytes[7]) & 0x3fff;
    }
  } // UUID timestamps are 100 nano-second units since the Gregorian epoch,
  // (1582-10-15 00:00).  JSNumbers aren't precise enough for this, so
  // time is handled internally as 'msecs' (integer milliseconds) and 'nsecs'
  // (100-nanoseconds offset from msecs) since unix epoch, 1970-01-01 00:00.


  let msecs = options.msecs !== undefined ? options.msecs : Date.now(); // Per 4.2.1.2, use count of uuid's generated during the current clock
  // cycle to simulate higher resolution clock

  let nsecs = options.nsecs !== undefined ? options.nsecs : _lastNSecs + 1; // Time since last uuid creation (in msecs)

  const dt = msecs - _lastMSecs + (nsecs - _lastNSecs) / 10000; // Per 4.2.1.2, Bump clockseq on clock regression

  if (dt < 0 && options.clockseq === undefined) {
    clockseq = clockseq + 1 & 0x3fff;
  } // Reset nsecs if clock regresses (new clockseq) or we've moved onto a new
  // time interval


  if ((dt < 0 || msecs > _lastMSecs) && options.nsecs === undefined) {
    nsecs = 0;
  } // Per 4.2.1.2 Throw error if too many uuids are requested


  if (nsecs >= 10000) {
    throw new Error("uuid.v1(): Can't create more than 10M uuids/sec");
  }

  _lastMSecs = msecs;
  _lastNSecs = nsecs;
  _clockseq = clockseq; // Per 4.1.4 - Convert from unix epoch to Gregorian epoch

  msecs += 12219292800000; // `time_low`

  const tl = ((msecs & 0xfffffff) * 10000 + nsecs) % 0x100000000;
  b[i++] = tl >>> 24 & 0xff;
  b[i++] = tl >>> 16 & 0xff;
  b[i++] = tl >>> 8 & 0xff;
  b[i++] = tl & 0xff; // `time_mid`

  const tmh = msecs / 0x100000000 * 10000 & 0xfffffff;
  b[i++] = tmh >>> 8 & 0xff;
  b[i++] = tmh & 0xff; // `time_high_and_version`

  b[i++] = tmh >>> 24 & 0xf | 0x10; // include version

  b[i++] = tmh >>> 16 & 0xff; // `clock_seq_hi_and_reserved` (Per 4.2.2 - include variant)

  b[i++] = clockseq >>> 8 | 0x80; // `clock_seq_low`

  b[i++] = clockseq & 0xff; // `node`

  for (let n = 0; n < 6; ++n) {
    b[i + n] = node[n];
  }

  return buf || (0, _stringify.default)(b);
}

var _default = v1;
exports["default"] = _default;

/***/ }),

/***/ 6409:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _v = _interopRequireDefault(__nccwpck_require__(5998));

var _md = _interopRequireDefault(__nccwpck_require__(4569));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const v3 = (0, _v.default)('v3', 0x30, _md.default);
var _default = v3;
exports["default"] = _default;

/***/ }),

/***/ 5998:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = _default;
exports.URL = exports.DNS = void 0;

var _stringify = _interopRequireDefault(__nccwpck_require__(8950));

var _parse = _interopRequireDefault(__nccwpck_require__(2746));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function stringToBytes(str) {
  str = unescape(encodeURIComponent(str)); // UTF8 escape

  const bytes = [];

  for (let i = 0; i < str.length; ++i) {
    bytes.push(str.charCodeAt(i));
  }

  return bytes;
}

const DNS = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';
exports.DNS = DNS;
const URL = '6ba7b811-9dad-11d1-80b4-00c04fd430c8';
exports.URL = URL;

function _default(name, version, hashfunc) {
  function generateUUID(value, namespace, buf, offset) {
    if (typeof value === 'string') {
      value = stringToBytes(value);
    }

    if (typeof namespace === 'string') {
      namespace = (0, _parse.default)(namespace);
    }

    if (namespace.length !== 16) {
      throw TypeError('Namespace must be array-like (16 iterable integer values, 0-255)');
    } // Compute hash of namespace and value, Per 4.3
    // Future: Use spread syntax when supported on all platforms, e.g. `bytes =
    // hashfunc([...namespace, ... value])`


    let bytes = new Uint8Array(16 + value.length);
    bytes.set(namespace);
    bytes.set(value, namespace.length);
    bytes = hashfunc(bytes);
    bytes[6] = bytes[6] & 0x0f | version;
    bytes[8] = bytes[8] & 0x3f | 0x80;

    if (buf) {
      offset = offset || 0;

      for (let i = 0; i < 16; ++i) {
        buf[offset + i] = bytes[i];
      }

      return buf;
    }

    return (0, _stringify.default)(bytes);
  } // Function#name is not settable on some platforms (#270)


  try {
    generateUUID.name = name; // eslint-disable-next-line no-empty
  } catch (err) {} // For CommonJS default export support


  generateUUID.DNS = DNS;
  generateUUID.URL = URL;
  return generateUUID;
}

/***/ }),

/***/ 5122:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _rng = _interopRequireDefault(__nccwpck_require__(807));

var _stringify = _interopRequireDefault(__nccwpck_require__(8950));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function v4(options, buf, offset) {
  options = options || {};

  const rnds = options.random || (options.rng || _rng.default)(); // Per 4.4, set bits for version and `clock_seq_hi_and_reserved`


  rnds[6] = rnds[6] & 0x0f | 0x40;
  rnds[8] = rnds[8] & 0x3f | 0x80; // Copy bytes to buffer, if provided

  if (buf) {
    offset = offset || 0;

    for (let i = 0; i < 16; ++i) {
      buf[offset + i] = rnds[i];
    }

    return buf;
  }

  return (0, _stringify.default)(rnds);
}

var _default = v4;
exports["default"] = _default;

/***/ }),

/***/ 9120:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _v = _interopRequireDefault(__nccwpck_require__(5998));

var _sha = _interopRequireDefault(__nccwpck_require__(5274));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const v5 = (0, _v.default)('v5', 0x50, _sha.default);
var _default = v5;
exports["default"] = _default;

/***/ }),

/***/ 6900:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _regex = _interopRequireDefault(__nccwpck_require__(814));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function validate(uuid) {
  return typeof uuid === 'string' && _regex.default.test(uuid);
}

var _default = validate;
exports["default"] = _default;

/***/ }),

/***/ 1595:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _validate = _interopRequireDefault(__nccwpck_require__(6900));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function version(uuid) {
  if (!(0, _validate.default)(uuid)) {
    throw TypeError('Invalid UUID');
  }

  return parseInt(uuid.substr(14, 1), 16);
}

var _default = version;
exports["default"] = _default;

/***/ }),

/***/ 7918:
/***/ (function(__unused_webpack_module, exports, __nccwpck_require__) {

"use strict";

var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.areFindingsEqual = exports.getImageScanFindings = void 0;
const core = __importStar(__nccwpck_require__(2186));
const client_ecr_1 = __nccwpck_require__(8923);
const scanner_1 = __nccwpck_require__(3232);
const promises_1 = __nccwpck_require__(8670);
const pendingStatus = [client_ecr_1.ScanStatus.PENDING, client_ecr_1.ScanStatus.IN_PROGRESS];
const readyStatus = [client_ecr_1.ScanStatus.COMPLETE, client_ecr_1.ScanStatus.ACTIVE];
const client = new client_ecr_1.ECRClient();
/**
 * @param {string} repository - ECR repo name
 * @param {string | undefined} registryId - ECR registry ID
 * @param {ImageIdentifier} imageIdentifier - image identifier
 * @param {string[]} ignore - VulnerabilityIds to ignore
 * @param {number} timeout - Time in seconds for scan to complete before failure
 * @param {number} pollRate - Time in seconds between polls complete scan status
 * @param {number} consistencyDelay - Time in seconds between polls for consistency
 * @param {string} [failOn] - Severity to cause failure
 * @returns {Promise<ScanFindings>}
 */
async function getImageScanFindings(repository, registryId, imageIdentifier, ignore, timeout, pollRate, consistencyDelay, failOn) {
    const command = new client_ecr_1.DescribeImageScanFindingsCommand({
        repositoryName: repository,
        registryId: registryId,
        imageId: imageIdentifier,
    });
    // Poll with delay untill we get 'COMPLETE' status.
    try {
        await pollForScanCompletion(command, pollRate * 1000, timeout);
    }
    catch (err) {
        if (err instanceof Error) {
            return { errorMessage: err.message };
        }
    }
    // Poll with consistencyDelay untill we get consistent data
    const findingSeverityCounts = await pollForConsistency(command, consistencyDelay * 1000);
    // No findings
    if (Object.keys(findingSeverityCounts).length === 0) {
        return { findingSeverityCounts: {} };
    }
    // No vulnerability > failOn or failOn not provided
    if (!failOn ||
        !doesContainFailOnVulnerabilty(findingSeverityCounts, failOn)) {
        return { findingSeverityCounts: findingSeverityCounts };
    }
    // Vulnerability > failOn found and no ignores provided
    if (ignore.length === 0) {
        return {
            findingSeverityCounts: findingSeverityCounts,
            errorMessage: `Found vulnerabilty with severity of ${failOn} or greater.`,
        };
    }
    // Vulnerability > failOn found after excluded ignores
    if (await doesContainNotIgnoredFailOnVulnerabilty(command, { ...findingSeverityCounts }, failOn, [...ignore])) {
        return {
            findingSeverityCounts: findingSeverityCounts,
            errorMessage: `Found vulnerabilty with severity of ${failOn} or greater.`,
        };
    }
    // Excluding ignores no Vulnerability failOn
    return {
        findingSeverityCounts: findingSeverityCounts,
    };
}
exports.getImageScanFindings = getImageScanFindings;
/**
 * Continues to send the provided command untill getting a 'COMPLETE' status
 * or timeout is reached.
 */
async function pollForScanCompletion(command, delay, timeout) {
    const timeoutMs = Date.now() + timeout * 1000;
    do {
        try {
            core.info(`Polling for complete scan...`);
            const resp = await client.send(command);
            if (readyStatus.includes(resp.imageScanStatus?.status)) {
                core.info(`Scan complete!`);
                return;
            }
            else if (pendingStatus.includes(resp.imageScanStatus?.status)) {
                core.info(`Scan status is "${resp.imageScanStatus?.status}"`);
            }
            else {
                throw new Error(`Unknown status: ${resp.imageScanStatus.status}`);
            }
        }
        catch (err) {
            if (err instanceof client_ecr_1.ImageNotFoundException) {
                core.info(err.message);
            }
            else if (err instanceof client_ecr_1.ScanNotFoundException) {
                core.info(err.message);
            }
            else {
                throw err;
            }
        }
        await (0, promises_1.setTimeout)(delay);
    } while (Date.now() < timeoutMs);
    throw new Error(`No complete scan after ${timeout} seconds`);
}
/**
 * Continues to call getAllSeverityCounts untill getting
 * the same result on subsequent calls. This is because after the aws ecr
 * api returns a status of COMPLETE, results continue to be be slowly updated
 * for a few seconds after
 */
async function pollForConsistency(command, delay) {
    if (delay === 0) {
        return getAllSeverityCounts(command);
    }
    let previousResult = undefined;
    while (true) {
        const currentResult = await getAllSeverityCounts(command);
        core.info(JSON.stringify(currentResult));
        if (previousResult && areFindingsEqual(currentResult, previousResult)) {
            core.info('Consistent Results!');
            return currentResult;
        }
        core.info('Polling for consitency...');
        previousResult = currentResult;
        await (0, promises_1.setTimeout)(delay);
    }
}
/**
 * Continues to send the provided command with the previous nextToken
 * and aggregating findingSeverityCounts untill the nextToken in not returned.
 * Returns the aggregated findingSeverityCounts.
 *
 * TODO: This is due to the annoying behaviour of the ecr api. When returning the paginated
 * findings, the aggregated summary is only based on the current page. Meaning to get
 * the full aggregated vulnerability counts we need to check all the pages. Update here if
 * they change this.
 */
async function getAllSeverityCounts(command) {
    const result = {};
    let nextToken = undefined;
    do {
        const nextCommand = new client_ecr_1.DescribeImageScanFindingsCommand({ ...command.input, nextToken });
        const page = await client.send(nextCommand);
        if (!page.imageScanFindings?.findingSeverityCounts) {
            return result;
        }
        for (const key in page.imageScanFindings.findingSeverityCounts) {
            const findingSeverity = key;
            if (result[key]) {
                result[key] +=
                    page.imageScanFindings.findingSeverityCounts[findingSeverity] || 0;
            }
            else {
                result[key] =
                    page.imageScanFindings.findingSeverityCounts[findingSeverity] || 0;
            }
        }
        nextToken = page.nextToken;
    } while (nextToken);
    return result;
}
/**
 * Checks if there are still vulnerabilities with severity > failOn
 * after removing vulnerabilites from ignore list and returns result.
 * Processes vulnerabilites in pages untill they are exhausted or all
 * items in the ignore list have been processed.
 */
async function doesContainNotIgnoredFailOnVulnerabilty(command, findingSeverityCounts, failOn, ignore) {
    let nextToken = undefined;
    do {
        const nextCommand = new client_ecr_1.DescribeImageScanFindingsCommand({ ...command.input, nextToken });
        const page = await client.send(nextCommand);
        page.imageScanFindings?.enhancedFindings?.forEach((vulnerabilty) => {
            const ignoreIndex = ignore.indexOf(vulnerabilty.packageVulnerabilityDetails.vulnerabilityId);
            if (ignoreIndex >= 0) {
                core.info(`Vulnerability ${vulnerabilty.packageVulnerabilityDetails
                    .vulnerabilityId} is ignored with ${vulnerabilty.severity} severity.`);
                findingSeverityCounts[vulnerabilty.severity] =
                    findingSeverityCounts[vulnerabilty.severity] - 1;
                ignore.splice(ignoreIndex, 1);
                if (!doesContainFailOnVulnerabilty(findingSeverityCounts, failOn)) {
                    return false;
                }
            }
        });
        nextToken = page.nextToken;
    } while (nextToken && ignore.length > 0);
    return doesContainFailOnVulnerabilty(findingSeverityCounts, failOn);
}
function doesContainFailOnVulnerabilty(findingSeverityCounts, failOn) {
    for (const severity in findingSeverityCounts) {
        if (scanner_1.findingSeverities[severity] <= scanner_1.findingSeverities[failOn] &&
            findingSeverityCounts[severity] > 0) {
            return true;
        }
    }
    return false;
}
function areFindingsEqual(f1, f2) {
    const keys = Object.keys(f1);
    if (keys.length != Object.keys(f2).length) {
        return false;
    }
    for (let i = 0; i < keys.length; i++) {
        if (f1[keys[i]] != f2[keys[i]]) {
            return false;
        }
    }
    return true;
}
exports.areFindingsEqual = areFindingsEqual;


/***/ }),

/***/ 6144:
/***/ (function(__unused_webpack_module, exports, __nccwpck_require__) {

"use strict";

var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.splitIgnoreList = exports.run = void 0;
const core = __importStar(__nccwpck_require__(2186));
const ecr_1 = __nccwpck_require__(7918);
const scanner_1 = __nccwpck_require__(3232);
const POLL_RATE = 5;
run();
async function run() {
    const repositoryInput = core.getInput('repository', { trimWhitespace: true });
    const registryIdInput = core.getInput('registry-id', {
        trimWhitespace: true,
    });
    const imageTagInput = core.getInput('image-tag', { trimWhitespace: true });
    const imageDigestInput = core.getInput('image-digest', {
        trimWhitespace: true,
    });
    const failOnInput = core
        .getInput('fail-on', { trimWhitespace: true })
        .toUpperCase();
    const ignoreInput = core.getInput('ignore', { trimWhitespace: true });
    const timeoutInput = core.getInput('timeout', { trimWhitespace: true });
    const consistencyDelayInput = core.getInput('consistency-delay', {
        trimWhitespace: true,
    });
    const registryId = registryIdInput === '' ? undefined : registryIdInput;
    const failOn = failOnInput === '' ? undefined : failOnInput;
    const imageTag = imageTagInput === '' ? undefined : imageTagInput;
    const imageDigest = imageDigestInput === '' ? undefined : imageDigestInput;
    const ignoreList = splitIgnoreList(ignoreInput);
    if (validateInput(registryId, failOn, timeoutInput, imageTag, imageDigest, consistencyDelayInput)) {
        try {
            const scanFindings = await (0, ecr_1.getImageScanFindings)(repositoryInput, registryId, { imageTag, imageDigest }, ignoreList, +timeoutInput, POLL_RATE, +consistencyDelayInput, failOn);
            core.setOutput('findingSeverityCounts', scanFindings.findingSeverityCounts);
            if (scanFindings.errorMessage) {
                core.setFailed(scanFindings.errorMessage);
            }
        }
        catch (err) {
            if (err instanceof Error) {
                core.setFailed(err.message);
            }
        }
    }
}
exports.run = run;
function validateInput(registryId, failOn, timeout, imageTag, imageDigest, consistencyDelay) {
    if (registryId && !/^\d{12}$/.test(registryId)) {
        core.setFailed(`Invalid registry-id: ${registryId}. Must be 12 digit number`);
        return false;
    }
    else if (failOn && scanner_1.findingSeverities[failOn] == undefined) {
        core.setFailed(`Invalid fail-on: ${failOn}`);
        return false;
    }
    else if (!isStringPositiveInteger(timeout)) {
        core.setFailed(`Invalid timeout: ${timeout}. Must be a positive integer`);
        return false;
    }
    else if (!isStringPositiveInteger(consistencyDelay)) {
        core.setFailed(`Invalid consistency-delay: ${consistencyDelay}. Must be a positive integer`);
        return false;
    }
    else if (!imageTag && !imageDigest) {
        core.setFailed(`Must provide at least 1 of image-tag OR image-digest`);
        return false;
    }
    return true;
}
function isStringPositiveInteger(input) {
    return !isNaN(+input) && Number.isInteger(+input) && +input >= 0;
}
function splitIgnoreList(ignore) {
    return ignore === ''
        ? []
        : ignore
            .trim()
            .replace(/\n+|\s+/g, ',')
            .replace(/,+/g, ',')
            .split(',')
            .map((cv) => cv.trim());
}
exports.splitIgnoreList = splitIgnoreList;


/***/ }),

/***/ 3232:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.findingSeverities = void 0;
exports.findingSeverities = {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
    INFORMATIONAL: 4,
    UNDEFINED: 4,
};


/***/ }),

/***/ 9491:
/***/ ((module) => {

"use strict";
module.exports = require("assert");

/***/ }),

/***/ 4300:
/***/ ((module) => {

"use strict";
module.exports = require("buffer");

/***/ }),

/***/ 2081:
/***/ ((module) => {

"use strict";
module.exports = require("child_process");

/***/ }),

/***/ 6113:
/***/ ((module) => {

"use strict";
module.exports = require("crypto");

/***/ }),

/***/ 2361:
/***/ ((module) => {

"use strict";
module.exports = require("events");

/***/ }),

/***/ 7147:
/***/ ((module) => {

"use strict";
module.exports = require("fs");

/***/ }),

/***/ 3292:
/***/ ((module) => {

"use strict";
module.exports = require("fs/promises");

/***/ }),

/***/ 3685:
/***/ ((module) => {

"use strict";
module.exports = require("http");

/***/ }),

/***/ 5158:
/***/ ((module) => {

"use strict";
module.exports = require("http2");

/***/ }),

/***/ 5687:
/***/ ((module) => {

"use strict";
module.exports = require("https");

/***/ }),

/***/ 1808:
/***/ ((module) => {

"use strict";
module.exports = require("net");

/***/ }),

/***/ 2037:
/***/ ((module) => {

"use strict";
module.exports = require("os");

/***/ }),

/***/ 1017:
/***/ ((module) => {

"use strict";
module.exports = require("path");

/***/ }),

/***/ 7282:
/***/ ((module) => {

"use strict";
module.exports = require("process");

/***/ }),

/***/ 2781:
/***/ ((module) => {

"use strict";
module.exports = require("stream");

/***/ }),

/***/ 8670:
/***/ ((module) => {

"use strict";
module.exports = require("timers/promises");

/***/ }),

/***/ 4404:
/***/ ((module) => {

"use strict";
module.exports = require("tls");

/***/ }),

/***/ 7310:
/***/ ((module) => {

"use strict";
module.exports = require("url");

/***/ }),

/***/ 3837:
/***/ ((module) => {

"use strict";
module.exports = require("util");

/***/ }),

/***/ 4289:
/***/ ((module) => {

"use strict";
module.exports = JSON.parse('{"name":"@aws-sdk/client-ecr","description":"AWS SDK for JavaScript Ecr Client for Node.js, Browser and React Native","version":"3.623.0","scripts":{"build":"concurrently \'yarn:build:cjs\' \'yarn:build:es\' \'yarn:build:types\'","build:cjs":"node ../../scripts/compilation/inline client-ecr","build:es":"tsc -p tsconfig.es.json","build:include:deps":"lerna run --scope $npm_package_name --include-dependencies build","build:types":"tsc -p tsconfig.types.json","build:types:downlevel":"downlevel-dts dist-types dist-types/ts3.4","clean":"rimraf ./dist-* && rimraf *.tsbuildinfo","extract:docs":"api-extractor run --local","generate:client":"node ../../scripts/generate-clients/single-service --solo ecr"},"main":"./dist-cjs/index.js","types":"./dist-types/index.d.ts","module":"./dist-es/index.js","sideEffects":false,"dependencies":{"@aws-crypto/sha256-browser":"5.2.0","@aws-crypto/sha256-js":"5.2.0","@aws-sdk/client-sso-oidc":"3.623.0","@aws-sdk/client-sts":"3.623.0","@aws-sdk/core":"3.623.0","@aws-sdk/credential-provider-node":"3.623.0","@aws-sdk/middleware-host-header":"3.620.0","@aws-sdk/middleware-logger":"3.609.0","@aws-sdk/middleware-recursion-detection":"3.620.0","@aws-sdk/middleware-user-agent":"3.620.0","@aws-sdk/region-config-resolver":"3.614.0","@aws-sdk/types":"3.609.0","@aws-sdk/util-endpoints":"3.614.0","@aws-sdk/util-user-agent-browser":"3.609.0","@aws-sdk/util-user-agent-node":"3.614.0","@smithy/config-resolver":"^3.0.5","@smithy/core":"^2.3.2","@smithy/fetch-http-handler":"^3.2.4","@smithy/hash-node":"^3.0.3","@smithy/invalid-dependency":"^3.0.3","@smithy/middleware-content-length":"^3.0.5","@smithy/middleware-endpoint":"^3.1.0","@smithy/middleware-retry":"^3.0.14","@smithy/middleware-serde":"^3.0.3","@smithy/middleware-stack":"^3.0.3","@smithy/node-config-provider":"^3.1.4","@smithy/node-http-handler":"^3.1.4","@smithy/protocol-http":"^4.1.0","@smithy/smithy-client":"^3.1.12","@smithy/types":"^3.3.0","@smithy/url-parser":"^3.0.3","@smithy/util-base64":"^3.0.0","@smithy/util-body-length-browser":"^3.0.0","@smithy/util-body-length-node":"^3.0.0","@smithy/util-defaults-mode-browser":"^3.0.14","@smithy/util-defaults-mode-node":"^3.0.14","@smithy/util-endpoints":"^2.0.5","@smithy/util-middleware":"^3.0.3","@smithy/util-retry":"^3.0.3","@smithy/util-utf8":"^3.0.0","@smithy/util-waiter":"^3.1.2","tslib":"^2.6.2"},"devDependencies":{"@tsconfig/node16":"16.1.3","@types/node":"^16.18.96","concurrently":"7.0.0","downlevel-dts":"0.10.1","rimraf":"3.0.2","typescript":"~4.9.5"},"engines":{"node":">=16.0.0"},"typesVersions":{"<4.0":{"dist-types/*":["dist-types/ts3.4/*"]}},"files":["dist-*/**"],"author":{"name":"AWS SDK for JavaScript Team","url":"https://aws.amazon.com/javascript/"},"license":"Apache-2.0","browser":{"./dist-es/runtimeConfig":"./dist-es/runtimeConfig.browser"},"react-native":{"./dist-es/runtimeConfig":"./dist-es/runtimeConfig.native"},"homepage":"https://github.com/aws/aws-sdk-js-v3/tree/main/clients/client-ecr","repository":{"type":"git","url":"https://github.com/aws/aws-sdk-js-v3.git","directory":"clients/client-ecr"}}');

/***/ }),

/***/ 9722:
/***/ ((module) => {

"use strict";
module.exports = JSON.parse('{"name":"@aws-sdk/client-sso-oidc","description":"AWS SDK for JavaScript Sso Oidc Client for Node.js, Browser and React Native","version":"3.623.0","scripts":{"build":"concurrently \'yarn:build:cjs\' \'yarn:build:es\' \'yarn:build:types\'","build:cjs":"node ../../scripts/compilation/inline client-sso-oidc","build:es":"tsc -p tsconfig.es.json","build:include:deps":"lerna run --scope $npm_package_name --include-dependencies build","build:types":"tsc -p tsconfig.types.json","build:types:downlevel":"downlevel-dts dist-types dist-types/ts3.4","clean":"rimraf ./dist-* && rimraf *.tsbuildinfo","extract:docs":"api-extractor run --local","generate:client":"node ../../scripts/generate-clients/single-service --solo sso-oidc"},"main":"./dist-cjs/index.js","types":"./dist-types/index.d.ts","module":"./dist-es/index.js","sideEffects":false,"dependencies":{"@aws-crypto/sha256-browser":"5.2.0","@aws-crypto/sha256-js":"5.2.0","@aws-sdk/core":"3.623.0","@aws-sdk/credential-provider-node":"3.623.0","@aws-sdk/middleware-host-header":"3.620.0","@aws-sdk/middleware-logger":"3.609.0","@aws-sdk/middleware-recursion-detection":"3.620.0","@aws-sdk/middleware-user-agent":"3.620.0","@aws-sdk/region-config-resolver":"3.614.0","@aws-sdk/types":"3.609.0","@aws-sdk/util-endpoints":"3.614.0","@aws-sdk/util-user-agent-browser":"3.609.0","@aws-sdk/util-user-agent-node":"3.614.0","@smithy/config-resolver":"^3.0.5","@smithy/core":"^2.3.2","@smithy/fetch-http-handler":"^3.2.4","@smithy/hash-node":"^3.0.3","@smithy/invalid-dependency":"^3.0.3","@smithy/middleware-content-length":"^3.0.5","@smithy/middleware-endpoint":"^3.1.0","@smithy/middleware-retry":"^3.0.14","@smithy/middleware-serde":"^3.0.3","@smithy/middleware-stack":"^3.0.3","@smithy/node-config-provider":"^3.1.4","@smithy/node-http-handler":"^3.1.4","@smithy/protocol-http":"^4.1.0","@smithy/smithy-client":"^3.1.12","@smithy/types":"^3.3.0","@smithy/url-parser":"^3.0.3","@smithy/util-base64":"^3.0.0","@smithy/util-body-length-browser":"^3.0.0","@smithy/util-body-length-node":"^3.0.0","@smithy/util-defaults-mode-browser":"^3.0.14","@smithy/util-defaults-mode-node":"^3.0.14","@smithy/util-endpoints":"^2.0.5","@smithy/util-middleware":"^3.0.3","@smithy/util-retry":"^3.0.3","@smithy/util-utf8":"^3.0.0","tslib":"^2.6.2"},"devDependencies":{"@tsconfig/node16":"16.1.3","@types/node":"^16.18.96","concurrently":"7.0.0","downlevel-dts":"0.10.1","rimraf":"3.0.2","typescript":"~4.9.5"},"engines":{"node":">=16.0.0"},"typesVersions":{"<4.0":{"dist-types/*":["dist-types/ts3.4/*"]}},"files":["dist-*/**"],"author":{"name":"AWS SDK for JavaScript Team","url":"https://aws.amazon.com/javascript/"},"license":"Apache-2.0","peerDependencies":{"@aws-sdk/client-sts":"^3.623.0"},"browser":{"./dist-es/runtimeConfig":"./dist-es/runtimeConfig.browser"},"react-native":{"./dist-es/runtimeConfig":"./dist-es/runtimeConfig.native"},"homepage":"https://github.com/aws/aws-sdk-js-v3/tree/main/clients/client-sso-oidc","repository":{"type":"git","url":"https://github.com/aws/aws-sdk-js-v3.git","directory":"clients/client-sso-oidc"}}');

/***/ }),

/***/ 1092:
/***/ ((module) => {

"use strict";
module.exports = JSON.parse('{"name":"@aws-sdk/client-sso","description":"AWS SDK for JavaScript Sso Client for Node.js, Browser and React Native","version":"3.623.0","scripts":{"build":"concurrently \'yarn:build:cjs\' \'yarn:build:es\' \'yarn:build:types\'","build:cjs":"node ../../scripts/compilation/inline client-sso","build:es":"tsc -p tsconfig.es.json","build:include:deps":"lerna run --scope $npm_package_name --include-dependencies build","build:types":"tsc -p tsconfig.types.json","build:types:downlevel":"downlevel-dts dist-types dist-types/ts3.4","clean":"rimraf ./dist-* && rimraf *.tsbuildinfo","extract:docs":"api-extractor run --local","generate:client":"node ../../scripts/generate-clients/single-service --solo sso"},"main":"./dist-cjs/index.js","types":"./dist-types/index.d.ts","module":"./dist-es/index.js","sideEffects":false,"dependencies":{"@aws-crypto/sha256-browser":"5.2.0","@aws-crypto/sha256-js":"5.2.0","@aws-sdk/core":"3.623.0","@aws-sdk/middleware-host-header":"3.620.0","@aws-sdk/middleware-logger":"3.609.0","@aws-sdk/middleware-recursion-detection":"3.620.0","@aws-sdk/middleware-user-agent":"3.620.0","@aws-sdk/region-config-resolver":"3.614.0","@aws-sdk/types":"3.609.0","@aws-sdk/util-endpoints":"3.614.0","@aws-sdk/util-user-agent-browser":"3.609.0","@aws-sdk/util-user-agent-node":"3.614.0","@smithy/config-resolver":"^3.0.5","@smithy/core":"^2.3.2","@smithy/fetch-http-handler":"^3.2.4","@smithy/hash-node":"^3.0.3","@smithy/invalid-dependency":"^3.0.3","@smithy/middleware-content-length":"^3.0.5","@smithy/middleware-endpoint":"^3.1.0","@smithy/middleware-retry":"^3.0.14","@smithy/middleware-serde":"^3.0.3","@smithy/middleware-stack":"^3.0.3","@smithy/node-config-provider":"^3.1.4","@smithy/node-http-handler":"^3.1.4","@smithy/protocol-http":"^4.1.0","@smithy/smithy-client":"^3.1.12","@smithy/types":"^3.3.0","@smithy/url-parser":"^3.0.3","@smithy/util-base64":"^3.0.0","@smithy/util-body-length-browser":"^3.0.0","@smithy/util-body-length-node":"^3.0.0","@smithy/util-defaults-mode-browser":"^3.0.14","@smithy/util-defaults-mode-node":"^3.0.14","@smithy/util-endpoints":"^2.0.5","@smithy/util-middleware":"^3.0.3","@smithy/util-retry":"^3.0.3","@smithy/util-utf8":"^3.0.0","tslib":"^2.6.2"},"devDependencies":{"@tsconfig/node16":"16.1.3","@types/node":"^16.18.96","concurrently":"7.0.0","downlevel-dts":"0.10.1","rimraf":"3.0.2","typescript":"~4.9.5"},"engines":{"node":">=16.0.0"},"typesVersions":{"<4.0":{"dist-types/*":["dist-types/ts3.4/*"]}},"files":["dist-*/**"],"author":{"name":"AWS SDK for JavaScript Team","url":"https://aws.amazon.com/javascript/"},"license":"Apache-2.0","browser":{"./dist-es/runtimeConfig":"./dist-es/runtimeConfig.browser"},"react-native":{"./dist-es/runtimeConfig":"./dist-es/runtimeConfig.native"},"homepage":"https://github.com/aws/aws-sdk-js-v3/tree/main/clients/client-sso","repository":{"type":"git","url":"https://github.com/aws/aws-sdk-js-v3.git","directory":"clients/client-sso"}}');

/***/ }),

/***/ 7947:
/***/ ((module) => {

"use strict";
module.exports = JSON.parse('{"name":"@aws-sdk/client-sts","description":"AWS SDK for JavaScript Sts Client for Node.js, Browser and React Native","version":"3.623.0","scripts":{"build":"concurrently \'yarn:build:cjs\' \'yarn:build:es\' \'yarn:build:types\'","build:cjs":"node ../../scripts/compilation/inline client-sts","build:es":"tsc -p tsconfig.es.json","build:include:deps":"lerna run --scope $npm_package_name --include-dependencies build","build:types":"rimraf ./dist-types tsconfig.types.tsbuildinfo && tsc -p tsconfig.types.json","build:types:downlevel":"downlevel-dts dist-types dist-types/ts3.4","clean":"rimraf ./dist-* && rimraf *.tsbuildinfo","extract:docs":"api-extractor run --local","generate:client":"node ../../scripts/generate-clients/single-service --solo sts","test":"yarn test:unit","test:unit":"jest"},"main":"./dist-cjs/index.js","types":"./dist-types/index.d.ts","module":"./dist-es/index.js","sideEffects":false,"dependencies":{"@aws-crypto/sha256-browser":"5.2.0","@aws-crypto/sha256-js":"5.2.0","@aws-sdk/client-sso-oidc":"3.623.0","@aws-sdk/core":"3.623.0","@aws-sdk/credential-provider-node":"3.623.0","@aws-sdk/middleware-host-header":"3.620.0","@aws-sdk/middleware-logger":"3.609.0","@aws-sdk/middleware-recursion-detection":"3.620.0","@aws-sdk/middleware-user-agent":"3.620.0","@aws-sdk/region-config-resolver":"3.614.0","@aws-sdk/types":"3.609.0","@aws-sdk/util-endpoints":"3.614.0","@aws-sdk/util-user-agent-browser":"3.609.0","@aws-sdk/util-user-agent-node":"3.614.0","@smithy/config-resolver":"^3.0.5","@smithy/core":"^2.3.2","@smithy/fetch-http-handler":"^3.2.4","@smithy/hash-node":"^3.0.3","@smithy/invalid-dependency":"^3.0.3","@smithy/middleware-content-length":"^3.0.5","@smithy/middleware-endpoint":"^3.1.0","@smithy/middleware-retry":"^3.0.14","@smithy/middleware-serde":"^3.0.3","@smithy/middleware-stack":"^3.0.3","@smithy/node-config-provider":"^3.1.4","@smithy/node-http-handler":"^3.1.4","@smithy/protocol-http":"^4.1.0","@smithy/smithy-client":"^3.1.12","@smithy/types":"^3.3.0","@smithy/url-parser":"^3.0.3","@smithy/util-base64":"^3.0.0","@smithy/util-body-length-browser":"^3.0.0","@smithy/util-body-length-node":"^3.0.0","@smithy/util-defaults-mode-browser":"^3.0.14","@smithy/util-defaults-mode-node":"^3.0.14","@smithy/util-endpoints":"^2.0.5","@smithy/util-middleware":"^3.0.3","@smithy/util-retry":"^3.0.3","@smithy/util-utf8":"^3.0.0","tslib":"^2.6.2"},"devDependencies":{"@tsconfig/node16":"16.1.3","@types/node":"^16.18.96","concurrently":"7.0.0","downlevel-dts":"0.10.1","rimraf":"3.0.2","typescript":"~4.9.5"},"engines":{"node":">=16.0.0"},"typesVersions":{"<4.0":{"dist-types/*":["dist-types/ts3.4/*"]}},"files":["dist-*/**"],"author":{"name":"AWS SDK for JavaScript Team","url":"https://aws.amazon.com/javascript/"},"license":"Apache-2.0","browser":{"./dist-es/runtimeConfig":"./dist-es/runtimeConfig.browser"},"react-native":{"./dist-es/runtimeConfig":"./dist-es/runtimeConfig.native"},"homepage":"https://github.com/aws/aws-sdk-js-v3/tree/main/clients/client-sts","repository":{"type":"git","url":"https://github.com/aws/aws-sdk-js-v3.git","directory":"clients/client-sts"}}');

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __nccwpck_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		var threw = true;
/******/ 		try {
/******/ 			__webpack_modules__[moduleId].call(module.exports, module, module.exports, __nccwpck_require__);
/******/ 			threw = false;
/******/ 		} finally {
/******/ 			if(threw) delete __webpack_module_cache__[moduleId];
/******/ 		}
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/compat */
/******/ 	
/******/ 	if (typeof __nccwpck_require__ !== 'undefined') __nccwpck_require__.ab = __dirname + "/";
/******/ 	
/************************************************************************/
/******/ 	
/******/ 	// startup
/******/ 	// Load entry module and return exports
/******/ 	// This entry module is referenced by other modules so it can't be inlined
/******/ 	var __webpack_exports__ = __nccwpck_require__(6144);
/******/ 	module.exports = __webpack_exports__;
/******/ 	
/******/ })()
;