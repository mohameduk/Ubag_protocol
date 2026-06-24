'use strict';

const { ubag }                                    = require('./middleware/express');
const { AgentCredential }                         = require('./AgentCredential');
const { Branch, resolveBranch }                   = require('./routing');
const { CREDENTIAL_HEADER, issueCredential, validateCredential } = require('./credential');
const { generateChallenge, verifyChallenge }      = require('./challenge');
const { buildAgentsJson }                         = require('./agentsJson');
const {
  generateAgentKeypair,
  agentSign,
  agentVerify,
  agentId,
  generateIssuerKeypair,
  issuerPublicFromPrivate,
  buildJwks,
}                                                 = require('./keys');

module.exports = {
  ubag,
  AgentCredential,
  Branch,
  resolveBranch,
  CREDENTIAL_HEADER,
  issueCredential,
  validateCredential,
  generateChallenge,
  verifyChallenge,
  buildAgentsJson,
  generateAgentKeypair,
  agentSign,
  agentVerify,
  agentId,
  generateIssuerKeypair,
  issuerPublicFromPrivate,
  buildJwks,
};
