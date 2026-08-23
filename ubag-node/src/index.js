'use strict';

const { ubag }                                    = require('./middleware/express');
const { AgentCredential }                         = require('./AgentCredential');
const { Branch, resolveBranch }                   = require('./routing');
const { CREDENTIAL_HEADER, issueCredential, validateCredential } = require('./credential');
const {
  MemoryReplayStore,
  ReplayStoreCapacityError,
  generateChallenge,
  verifyChallenge,
} = require('./challenge');
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
// Scoped retrieval: the free, universal half of the protocol. Deliberately
// not gated, because the value of an agent identity grows with the number of
// sites that answer one.
const {
  indexFields,
  manifest,
  resolve,
  parseFields,
  splitUbagQuery,
  shapePayload,
}                                                 = require('./scoped');
const { Agent, ChallengeFailed, NotIdentified }   = require('./client');
const {
  ProvenanceError,
  parseProvenance,
  createProvenance,
  verifyProvenance,
}                                                 = require('./provenance');

module.exports = {
  ubag,
  AgentCredential,
  Agent,
  ChallengeFailed,
  NotIdentified,
  indexFields,
  manifest,
  resolve,
  parseFields,
  splitUbagQuery,
  shapePayload,
  Branch,
  resolveBranch,
  CREDENTIAL_HEADER,
  issueCredential,
  validateCredential,
  MemoryReplayStore,
  ReplayStoreCapacityError,
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
  ProvenanceError,
  parseProvenance,
  createProvenance,
  verifyProvenance,
};
