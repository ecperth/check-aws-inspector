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
Object.defineProperty(exports, "__esModule", { value: true });
exports.areFindingsEqual = exports.getImageScanFindings = void 0;
const core = __importStar(require("@actions/core"));
const client_ecr_1 = require("@aws-sdk/client-ecr");
const scanner_1 = require("./scanner");
const promises_1 = require("timers/promises");
const client = new client_ecr_1.ECRClient();
/**
 * @param {string} repository - ECR repo name
 * @param {tag} tag - Image tag
 * @param {string[]} ignore - VulnerabilityIds to ignore
 * @param {number} timeout - Time in seconds for scan to complete before failure
 * @param {number} pollRate - Time in seconds between polls complete scan status
 * @param {number} consistencyDelay - Time in seconds between polls for consistency
 * @param {string} [failOn] - Severity to cause failure
 * @returns {Promise<ScanFindings>}
 */
async function getImageScanFindings(repository, tag, ignore, timeout, pollRate, consistencyDelay, failOn) {
    const command = new client_ecr_1.DescribeImageScanFindingsCommand({
        repositoryName: repository,
        imageId: {
            imageTag: tag,
        },
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
        core.info(`Polling for complete scan...`);
        const resp = await client.send(command);
        if (resp.imageScanStatus?.status === 'COMPLETE') {
            core.info(`Scan complete!`);
            return;
        }
        else if (resp.imageScanStatus?.status === 'PENDING') {
            core.info(`Scan status is "Pending"`);
        }
        else {
            throw new Error(`Unknown status: ${resp.imageScanStatus.status}`);
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
 */
async function getAllSeverityCounts(command) {
    const result = {};
    do {
        const page = await client.send(command);
        if (!page.imageScanFindings?.findingSeverityCounts) {
            return result;
        }
        Object.keys(page.imageScanFindings.findingSeverityCounts).forEach((key) => {
            if (result[key]) {
                result[key] =
                    result[key] + page.imageScanFindings.findingSeverityCounts[key];
            }
            else {
                result[key] = page.imageScanFindings.findingSeverityCounts[key];
            }
        });
        command.input.nextToken = page.nextToken;
    } while (command.input.nextToken);
    return result;
}
/**
 * Checks if there are still vulnerabilities with severity > failOn
 * after removing vulnerabilites from ignore list and returns result.
 * Processes vulnerabilites in pages untill they are exhausted or all
 * items in the ignore list have been processed.
 */
async function doesContainNotIgnoredFailOnVulnerabilty(command, findingSeverityCounts, failOn, ignore) {
    do {
        const resp = await client.send(command);
        resp.imageScanFindings?.enhancedFindings?.forEach((vulnerabilty) => {
            const ignoreIndex = ignore.indexOf(vulnerabilty.packageVulnerabilityDetails.vulnerabilityId);
            if (ignoreIndex >= 0) {
                core.info(`Vulnerability ${vulnerabilty.packageVulnerabilityDetails
                    .vulnerabilityId} is ignored. Decrementing the ${vulnerabilty.severity} severity count.`);
                findingSeverityCounts[vulnerabilty.severity] =
                    findingSeverityCounts[vulnerabilty.severity] - 1;
                ignore.splice(ignoreIndex, 1);
                if (!doesContainFailOnVulnerabilty(findingSeverityCounts, failOn)) {
                    return false;
                }
            }
            command.input.nextToken = resp.nextToken;
        });
    } while (command.input.nextToken && ignore.length > 0);
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
//# sourceMappingURL=ecr.js.map