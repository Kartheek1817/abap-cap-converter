package com.example.abapcap;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.*;
import java.util.regex.*;

@RestController
@RequestMapping("/api")
public class AbapCapController {

    // ── Config ────────────────────────────────────────────────────────────────
    @Value("${gemini.api.key}")      private String geminiKey;
    @Value("${gemini.model}")        private String geminiModel;
    @Value("${deepseek.api.key}")    private String deepseekKey;
    @Value("${deepseek.model}")      private String deepseekModel;
    @Value("${deepseek.base.url}")   private String deepseekUrl;
    @Value("${nvidia.api.key}")      private String nvidiaKey;
    @Value("${nvidia.model}")        private String nvidiaModel;
    @Value("${nvidia.base.url}")     private String nvidiaUrl;

    private final ObjectMapper mapper  = new ObjectMapper();
    private final RestTemplate http    = new RestTemplate();

    // ══════════════════════════════════════════════════════════════════════════
    // SYSTEM PROMPTS
    // ══════════════════════════════════════════════════════════════════════════

    // ── Call 1: ABAP Analysis prompt ─────────────────────────────────────────
    private static final String ANALYSIS_SYSTEM = """
You are an expert SAP ABAP code analyzer.
Analyze the given ABAP code and return ONLY a valid JSON object — no markdown, no explanation, no code fences.

Return this exact JSON structure:
{
  "entities": [
    {
      "name": "EntityName",
      "abapTable": "TABLE_NAME",
      "fields": [
        { "name": "fieldName", "abapField": "ABAP_FIELD", "type": "String|Integer|Decimal|Date|Boolean|UUID" }
      ]
    }
  ],
  "relationships": [
    { "from": "EntityA", "to": "EntityB", "type": "many-to-one", "foreignKey": "fieldName" }
  ],
  "operations": ["READ", "CREATE", "UPDATE", "DELETE", "FILTER"],
  "complexity": "Simple|Medium|Complex",
  "confidenceScore": 85,
  "migrationNotes": [
    "KNA1 table mapped to Customers entity",
    "SELECT with WHERE converted to OData $filter"
  ],
  "warnings": [
    "Dynamic SQL found — converted to static OData filter",
    "ABAP-specific logic in line 45 needs manual review"
  ]
}

Rules:
- entities: one per ABAP table or main data object found
- operations: only include operations actually present in the code
- confidenceScore: 0-100, how confident you are the conversion will be accurate
- migrationNotes: positive things that mapped well (shown as green ✓)
- warnings: things that need attention (shown as orange ⚠)
- Return ONLY the JSON. No other text at all.
""";

    // ── Call 2: CAP Generation system prompt ──────────────────────────────────
    private static final String GENERATION_SYSTEM = """
You are an expert SAP CAP (Cloud Application Programming model) developer.
You will receive a JSON analysis of an ABAP application.
Generate a complete SAP CAP application from this analysis.

══════════════════════════════════════════════════════════════
OUTPUT FORMAT — EXACTLY 8 ---FILE--- blocks, nothing else:
══════════════════════════════════════════════════════════════
---FILE:db/schema.cds:cds---
content
---ENDFILE---
---FILE:srv/service.cds:cds---
content
---ENDFILE---
---FILE:srv/service.js:javascript---
content
---ENDFILE---
---FILE:app/controller/Main.controller.js:javascript---
content
---ENDFILE---
---FILE:app/view/Main.view.xml:xml---
content
---ENDFILE---
---FILE:package.json:json---
content
---ENDFILE---
---FILE:.cdsrc.json:json---
content
---ENDFILE---
---FILE:data/db-Entity.csv:csv---
content
---ENDFILE---

══════════════════════════════════════════════════════════════
BLUEPRINT — db/schema.cds
══════════════════════════════════════════════════════════════
namespace com.abap.migration;
using { cuid, managed } from '@sap/cds/common';

entity Customers : cuid, managed {
  name    : String(100)  @mandatory;
  country : String(3);
  city    : String(50);
  orders  : Association to many Orders on orders.customer = $self;
}

entity Orders : cuid, managed {
  orderNumber : String(20) @mandatory;
  amount      : Decimal(15,2);
  currency    : String(3) default 'USD';
  status      : String(20) @assert.range enum { Open; InProgress; Closed; };
  customer    : Association to Customers;
}

══════════════════════════════════════════════════════════════
BLUEPRINT — srv/service.cds
══════════════════════════════════════════════════════════════
using { com.abap.migration as db } from '../db/schema';

service MainService @(path: '/main') {

  @readonly
  entity Customers as projection on db.Customers {
    *,
    orders : redirected to Orders
  }

  entity Orders as projection on db.Orders {
    *,
    customer : redirected to Customers
  }

  action  createOrder(customerId: UUID, amount: Decimal) returns Orders;
  function getTotalRevenue()                              returns Decimal;
}

annotate MainService.Customers with @(
  UI.LineItem: [
    { $Type: 'UI.DataField', Value: name,    Label: 'Customer Name' },
    { $Type: 'UI.DataField', Value: country, Label: 'Country'       },
    { $Type: 'UI.DataField', Value: city,    Label: 'City'          }
  ],
  UI.SelectionFields: [ name, country ]
);

annotate MainService.Orders with @(
  UI.LineItem: [
    { $Type: 'UI.DataField', Value: orderNumber, Label: 'Order #'  },
    { $Type: 'UI.DataField', Value: amount,      Label: 'Amount'   },
    { $Type: 'UI.DataField', Value: status,      Label: 'Status'   }
  ]
);

══════════════════════════════════════════════════════════════
BLUEPRINT — srv/service.js
══════════════════════════════════════════════════════════════
const cds = require('@sap/cds');

module.exports = cds.service.impl(async function (srv) {
  const { Customers, Orders } = srv.entities;

  // Before CREATE — set defaults
  srv.before('CREATE', Orders, req => {
    req.data.status   = req.data.status   || 'Open';
    req.data.currency = req.data.currency || 'USD';
  });

  // After READ — enrich data
  srv.after('READ', Customers, rows => {
    rows.forEach(row => {
      row.displayName = `${row.name} (${row.country || '?'})`;
    });
  });

  // Custom action
  srv.on('createOrder', async req => {
    const { customerId, amount } = req.data;
    const order = await INSERT.into(Orders).entries({
      orderNumber: `ORD-${Date.now()}`,
      customer_ID: customerId,
      amount,
      status: 'Open',
    });
    return order;
  });

  // Custom function
  srv.on('getTotalRevenue', async req => {
    const result = await SELECT.one`sum(amount) as total`.from(Orders);
    return result?.total ?? 0;
  });
});

══════════════════════════════════════════════════════════════
BLUEPRINT — app/controller/Main.controller.js
══════════════════════════════════════════════════════════════
sap.ui.define([
  "sap/ui/core/mvc/Controller",
  "sap/ui/model/json/JSONModel",
  "sap/m/MessageToast",
  "sap/ui/model/Filter",
  "sap/ui/model/FilterOperator"
], function(Controller, JSONModel, MessageToast, Filter, FilterOperator) {
  "use strict";
  return Controller.extend("com.abap.migration.controller.Main", {

    onInit: function() {
      // JSONModel is set by the preview frame with CSV data
      // No need to set model here — it comes from CSV
    },

    onSearch: function(oEvent) {
      var sQuery = oEvent.getParameter("newValue") || "";
      var oTable = this.byId("mainTable") || this.byId("mainList");
      if (!oTable) return;
      var oBinding = oTable.getBinding("items");
      if (!oBinding) return;
      if (sQuery.trim()) {
        // Filter by name or first string field
        oBinding.filter([new Filter("name", FilterOperator.Contains, sQuery)]);
      } else {
        oBinding.filter([]);
      }
    },

    onCreate: function() {
      MessageToast.show("Create new record — connect to OData service in production.");
    },

    onItemPress: function(oEvent) {
      var oItem = oEvent.getSource();
      var oCtx  = oItem.getBindingContext();
      if (oCtx) {
        var oData = oCtx.getObject();
        MessageToast.show("Selected: " + (oData.name || oData.id || "Item"));
      }
    },

    onExport: function() {
      MessageToast.show("Export — connect to sap.ui.export.Spreadsheet in production.");
    },

    onFilter: function() {
      MessageToast.show("Filter — connect to sap.m.ViewSettingsDialog in production.");
    }
  });
});

══════════════════════════════════════════════════════════════
BLUEPRINT — app/view/Main.view.xml (UI5 Fiori view for preview)
══════════════════════════════════════════════════════════════
CRITICAL RULES FOR THIS FILE:
- This is the UI5 XML view that gets rendered in the iframe preview
- Use sap.f.DynamicPage as root — NEVER sap.m.Page
- Use IllustratedMessage for empty states — NEVER noDataText attribute
- Use DynamicPage, Table, SearchField, OverflowToolbar
- Controller: com.abap.migration.controller.Main
- Include realistic sample data in the controller (JSONModel)
- NEVER use ShellBar — handled by preview shell
- NEVER use ComponentSupport or data-sap-ui-oninit

<mvc:View
  xmlns:mvc="sap.ui.core.mvc"
  xmlns="sap.m"
  xmlns:f="sap.f"
  xmlns:core="sap.ui.core"
  xmlns:form="sap.ui.layout.form"
  controllerName="com.abap.migration.controller.Main"
  displayBlock="true">
  <f:DynamicPage id="mainPage" headerExpanded="true" toggleHeaderOnTitleClick="false">
    <f:title>
      <f:DynamicPageTitle>
        <f:heading><Title text="Customers" level="H2"/></f:heading>
        <f:actions>
          <Button text="Create" type="Emphasized" press=".onCreate" icon="sap-icon://add"/>
          <Button icon="sap-icon://excel-attachment" type="Transparent" press=".onExport"/>
        </f:actions>
      </f:DynamicPageTitle>
    </f:title>
    <f:content>
      <VBox>
        <Table id="mainTable" items="{/items}" growing="true" growingThreshold="10">
          <noData>
            <IllustratedMessage illustrationType="sapIllus-EmptyList"
              title="No records found" description="Try adjusting your search"/>
          </noData>
          <headerToolbar>
            <OverflowToolbar>
              <Title text="Records" level="H3"/>
              <ToolbarSpacer/>
              <SearchField width="200px" liveChange=".onSearch" placeholder="Search..."/>
            </OverflowToolbar>
          </headerToolbar>
          <columns>
            <Column><Text text="Name"/></Column>
            <Column><Text text="Country"/></Column>
            <Column><Text text="Status"/></Column>
          </columns>
          <items>
            <ColumnListItem type="Navigation" press=".onItemPress">
              <cells>
                <ObjectIdentifier title="{name}" text="{id}"/>
                <Text text="{country}"/>
                <ObjectStatus text="{status}" state="{statusState}"/>
              </cells>
            </ColumnListItem>
          </items>
        </Table>
      </VBox>
    </f:content>
  </f:DynamicPage>
</mvc:View>

══════════════════════════════════════════════════════════════
BLUEPRINT — package.json
══════════════════════════════════════════════════════════════
{
  "name": "abap-migration-app",
  "version": "1.0.0",
  "description": "SAP CAP application migrated from ABAP",
  "engines": { "node": ">=18" },
  "dependencies": {
    "@sap/cds": "^7",
    "@sap/cds-dk": "^7",
    "express": "^4"
  },
  "devDependencies": {
    "@cap-js/sqlite": "^1"
  },
  "scripts": {
    "start":   "cds-serve",
    "dev":     "cds watch",
    "test":    "cds bind --exec jest"
  },
  "cds": {
    "requires": {
      "db": { "kind": "sqlite", "credentials": { "url": ":memory:" } }
    }
  }
}

══════════════════════════════════════════════════════════════
BLUEPRINT — .cdsrc.json
══════════════════════════════════════════════════════════════
{
  "build": { "target": "gen", "src": "db" },
  "odata": { "version": "v4" },
  "requires": {
    "db": {
      "kind": "sqlite",
      "credentials": { "url": "db.sqlite" }
    }
  },
  "features": {
    "fiori_preview": true,
    "draft_compat":  true
  }
}

══════════════════════════════════════════════════════════════
STRICTLY FORBIDDEN — TABLE COLUMN RULES (most common mistakes):
══════════════════════════════════════════════════════════════
❌ <ObjectIdentifier> inside table ColumnListItem cells
   → ALWAYS use <Text text="{field}"/> in table cells
   → ObjectIdentifier shows TWO lines (title + text) = breaks column layout
   → ONLY use <Text> or <ObjectStatus> or <ObjectNumber> in table cells

❌ Mismatched columns count:
   → Number of <Column> in <columns> MUST exactly match
     number of cells in <ColumnListItem><cells>
   → If you have 4 <Column> tags you MUST have exactly 4 cell controls

❌ <ObjectIdentifier> anywhere in tables → use <Text>
❌ xmlns:f="sap.ui.layout.form"  → use xmlns:form="sap.ui.layout.form"
❌ <f:SimpleForm>                → use <form:SimpleForm>
❌ sap.m.Page                    → use sap.f.DynamicPage
❌ noDataText="..."              → use <noData><IllustratedMessage.../></noData>
❌ ShellBar in XML view
❌ ComponentSupport or data-sap-ui-oninit in view XML
❌ <FlexBox>                     → use <HBox> or <VBox>
❌ <GenericCard>                 → does not exist, use <GenericTile>
❌ Multiple children in f:content → always wrap in single <VBox>
❌ Markdown code fences in output (no ```)
❌ Any text outside the 8 ---FILE--- blocks

CORRECT TABLE CELL PATTERN — always follow this:
<columns>
  <Column><Text text="ID"/></Column>
  <Column><Text text="Name"/></Column>
  <Column><Text text="Status"/></Column>
  <Column><Text text="Amount"/></Column>
</columns>
<items>
  <ColumnListItem type="Navigation" press=".onItemPress">
    <cells>
      <Text text="{id}"/>
      <Text text="{name}"/>
      <ObjectStatus text="{status}" state="{statusState}"/>
      <ObjectNumber number="{amount}" unit="USD"/>
    </cells>
  </ColumnListItem>
</items>
Rule: 4 columns = exactly 4 cells. Use Text for simple values. NEVER ObjectIdentifier.

══════════════════════════════════════════════════════════════
QUALITY CHECKLIST (verify before outputting):
══════════════════════════════════════════════════════════════
✅ db/schema.cds: all entities have 'key ID : UUID' or cuid mixin
✅ db/schema.cds: associations defined for all relationships
✅ srv/service.cds: all entities exposed in service
✅ srv/service.js: before/after hooks for main operations
✅ app/view/Main.view.xml: uses DynamicPage, NOT sap.m.Page
✅ app/view/Main.view.xml: IllustratedMessage for empty state, NOT noDataText
✅ app/view/Main.view.xml: column count EXACTLY matches cell count in ColumnListItem
✅ app/view/Main.view.xml: NO ObjectIdentifier inside table cells — use Text only
✅ app/view/Main.view.xml: JSONModel with 5 realistic sample records in onInit
✅ app/view/Main.view.xml: SearchField with liveChange=".onSearch"
✅ app/view/Main.view.xml: f:content has ONE direct child (VBox wrapping everything)
✅ data CSV: header row names MUST exactly match XML binding paths
   Example: if XML has text="{customerName}" → CSV header must be "customerName" (same case)
   Example: if XML has text="{age}" → CSV header must be "age" not "Age" or "AGE"
✅ data CSV: MUST have 5 rows of realistic mock data — never leave rows empty
✅ data CSV: every column must have data in every row — no empty cells
✅ app/controller: generate a working controller.js that handles onSearch, onCreate, onItemPress with MessageToast
✅ Exactly 8 ---FILE--- blocks, nothing else, no text before first block
""";

    // ── Conversational system prompt ──────────────────────────────────────────
    private static final String CHAT_SYSTEM = """
You are an expert SAP CAP developer and ABAP migration specialist assistant.
You are having a conversation with a developer who is working on migrating ABAP code to SAP CAP.

You have two modes:

MODE 1 — QUESTION (user asks something):
If user asks "what is", "how does", "explain", "why", etc. — answer conversationally in plain text.
Be helpful, clear, and concise. No file blocks needed.

MODE 2 — MODIFY (user wants to change the app):
If user says "add", "change", "remove", "update", "modify", etc. — update the CAP files.
Return ONLY the files that changed using ---FILE--- blocks.
Do not return all 7 files if only 1-2 changed.
After the file blocks, write a short summary of what you changed.

FORMAT for modifications:
---FILE:path/to/file:language---
content
---ENDFILE---

[Then a short explanation of what changed]

IMPORTANT:
- If modifying, I will give you the current XML view and schema.cds
- Keep changes minimal — only modify what was asked
- Never break existing functionality
- Always use DynamicPage, never sap.m.Page
- Always keep IllustratedMessage for empty states
- CRITICAL CSV RULE: if you add/remove table columns in the XML view,
  you MUST also return an updated CSV file where header names EXACTLY
  match the XML binding paths (lowercase, case-sensitive).
  Example: if XML has text="{age}" the CSV header must be "age" not "Age"
""";

    // ══════════════════════════════════════════════════════════════════════════
    // REQUEST / RESPONSE MODELS
    // ══════════════════════════════════════════════════════════════════════════

    public record ConvertRequest(
        String abapCode,
        String model,
        List<Map<String, String>> chatHistory
    ) {}

    public record ChatRequest(
        String message,
        String model,
        String currentXml,
        String currentSchema,
        String currentCsv,
        String currentCsvPath,
        List<Map<String, String>> chatHistory
    ) {}

    public record GeneratedFile(String path, String language, String content) {}

    public record ConvertResponse(
        List<GeneratedFile> files,
        Map<String, Object> analysis,
        String chatMessage
    ) {}

    public record ChatResponse(
        List<GeneratedFile> files,
        String chatMessage
    ) {}

    // ══════════════════════════════════════════════════════════════════════════
    // ENDPOINTS
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * POST /api/convert
     * Main endpoint — takes ABAP code, does 2 AI calls, returns 7 CAP files
     */
    @PostMapping("/convert")
    public ResponseEntity<?> convert(@RequestBody ConvertRequest req) {
        try {
            if (req.abapCode() == null || req.abapCode().isBlank()) {
                return ResponseEntity.badRequest().body(Map.of("error", "ABAP code is required"));
            }

            String model = req.model() != null ? req.model() : "gemini";

            // ── CALL 1: Analyze ABAP → get JSON summary ───────────────────
            String analysisJson = callAnalysis(req.abapCode(), model);
            Map<String, Object> analysis = parseAnalysisJson(analysisJson);

            // ── CALL 2: Generate CAP files from JSON summary ──────────────
            String generationPrompt = buildGenerationPrompt(analysisJson, req.abapCode());
            String rawResponse = callGeneration(generationPrompt, model);

            // ── Parse ---FILE--- blocks ───────────────────────────────────
            List<GeneratedFile> files = parseFileBlocks(rawResponse);

            if (files.isEmpty()) {
                // Retry once if no blocks found
                System.out.println("No file blocks found — retrying...");
                rawResponse = callGeneration(buildRetryPrompt(analysisJson), model);
                files = parseFileBlocks(rawResponse);
            }

            // Sanitize the XML view file
            files = sanitizeFiles(files);

            int score = (int) analysis.getOrDefault("confidenceScore", 75);
            String chatMsg = String.format(
                "Generated %d CAP files! Migration score: %d%%. " +
                "Found %s entities. You can ask me to modify anything.",
                files.size(), score,
                ((List<?>) analysis.getOrDefault("entities", List.of())).size()
            );

            return ResponseEntity.ok(new ConvertResponse(files, analysis, chatMsg));

        } catch (Exception e) {
            System.err.println("Convert error: " + e.getMessage());
            return ResponseEntity.status(500).body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * POST /api/chat
     * Conversational endpoint — modify existing CAP or answer questions
     */
    @PostMapping("/chat")
    public ResponseEntity<?> chat(@RequestBody ChatRequest req) {
        try {
            String model = req.model() != null ? req.model() : "gemini";

            String userContent = buildChatUserMessage(req);
            String rawResponse = callChat(userContent, req.chatHistory(), model);

            // Check if response contains ---FILE--- blocks (modification)
            List<GeneratedFile> files = parseFileBlocks(rawResponse);

            // Extract text part (after the last ---ENDFILE--- block)
            String chatMsg = extractChatMessage(rawResponse, files.isEmpty());

            if (!files.isEmpty()) {
                files = sanitizeFiles(files);
                if (chatMsg.isBlank()) chatMsg = "Done! I've updated the files.";
            }

            return ResponseEntity.ok(new ChatResponse(
                files.isEmpty() ? null : files,
                chatMsg
            ));

        } catch (Exception e) {
            System.err.println("Chat error: " + e.getMessage());
            return ResponseEntity.status(500).body(Map.of("error", e.getMessage()));
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // AI CALL METHODS
    // ══════════════════════════════════════════════════════════════════════════

    private String callAnalysis(String abapCode, String model) throws Exception {
        String userMsg = "Analyze this ABAP code and return the JSON analysis:\n\n" + abapCode;
        return callAi(ANALYSIS_SYSTEM, userMsg, model, 2000);
    }

    private String callGeneration(String prompt, String model) throws Exception {
        return callAi(GENERATION_SYSTEM, prompt, model, 8000);
    }

    private String callChat(String userMsg,
                            List<Map<String, String>> history,
                            String model) throws Exception {
        return callAiWithHistory(CHAT_SYSTEM, history, userMsg, model, 6000);
    }

    // ── Unified AI dispatcher ─────────────────────────────────────────────────
    private String callAi(String system, String user, String model, int maxTokens) throws Exception {
        return switch (model.toLowerCase()) {
            case "gemini"   -> callGemini(system, List.of(), user, maxTokens);
            case "deepseek" -> callOpenAiStyle(system, List.of(), user, maxTokens,
                                               deepseekUrl, deepseekKey, deepseekModel);
            case "llama"    -> callOpenAiStyle(system, List.of(), user, maxTokens,
                                               nvidiaUrl, nvidiaKey, nvidiaModel);
            default         -> callGemini(system, List.of(), user, maxTokens);
        };
    }

    private String callAiWithHistory(String system,
                                     List<Map<String, String>> history,
                                     String user,
                                     String model,
                                     int maxTokens) throws Exception {
        return switch (model.toLowerCase()) {
            case "gemini"   -> callGemini(system, history, user, maxTokens);
            case "deepseek" -> callOpenAiStyle(system, history, user, maxTokens,
                                               deepseekUrl, deepseekKey, deepseekModel);
            case "llama"    -> callOpenAiStyle(system, history, user, maxTokens,
                                               nvidiaUrl, nvidiaKey, nvidiaModel);
            default         -> callGemini(system, history, user, maxTokens);
        };
    }

    // ── Gemini API ────────────────────────────────────────────────────────────
    private String callGemini(String system,
                               List<Map<String, String>> history,
                               String user,
                               int maxTokens) throws Exception {
        String url = "https://generativelanguage.googleapis.com/v1beta/models/"
                   + geminiModel + ":generateContent?key=" + geminiKey;

        ObjectNode body = mapper.createObjectNode();

        // System instruction
        ObjectNode sysNode = mapper.createObjectNode();
        ObjectNode sysPart = mapper.createObjectNode();
        sysPart.put("text", system);
        sysNode.set("parts", mapper.createArrayNode().add(sysPart));
        body.set("systemInstruction", sysNode);

        // Contents (history + current)
        ArrayNode contents = mapper.createArrayNode();
        for (Map<String, String> msg : history) {
            ObjectNode m    = mapper.createObjectNode();
            ObjectNode part = mapper.createObjectNode();
            part.put("text", msg.get("content"));
            m.put("role", "user".equals(msg.get("role")) ? "user" : "model");
            m.set("parts", mapper.createArrayNode().add(part));
            contents.add(m);
        }
        ObjectNode userNode = mapper.createObjectNode();
        ObjectNode userPart = mapper.createObjectNode();
        userPart.put("text", user);
        userNode.put("role", "user");
        userNode.set("parts", mapper.createArrayNode().add(userPart));
        contents.add(userNode);
        body.set("contents", contents);

        // Generation config
        ObjectNode config = mapper.createObjectNode();
        config.put("maxOutputTokens", maxTokens);
        config.put("temperature", 0.2);
        body.set("generationConfig", config);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> entity = new HttpEntity<>(mapper.writeValueAsString(body), headers);

        ResponseEntity<String> res = http.postForEntity(url, entity, String.class);
        JsonNode root = mapper.readTree(res.getBody());
        return root.path("candidates").path(0)
                   .path("content").path("parts").path(0)
                   .path("text").asText("");
    }

    // ── OpenAI-style API (DeepSeek via OpenRouter + Llama via NVIDIA) ─────────
    private String callOpenAiStyle(String system,
                                   List<Map<String, String>> history,
                                   String user,
                                   int maxTokens,
                                   String url,
                                   String apiKey,
                                   String modelName) throws Exception {
        ObjectNode body = mapper.createObjectNode();
        body.put("model", modelName);
        body.put("max_tokens", maxTokens);
        body.put("temperature", 0.2);

        ArrayNode messages = mapper.createArrayNode();

        // System message
        ObjectNode sysMsg = mapper.createObjectNode();
        sysMsg.put("role", "system");
        sysMsg.put("content", system);
        messages.add(sysMsg);

        // History
        for (Map<String, String> msg : history) {
            ObjectNode m = mapper.createObjectNode();
            m.put("role", msg.get("role"));
            m.put("content", msg.get("content"));
            messages.add(m);
        }

        // Current user message
        ObjectNode userMsg = mapper.createObjectNode();
        userMsg.put("role", "user");
        userMsg.put("content", user);
        messages.add(userMsg);

        body.set("messages", messages);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(apiKey);
        HttpEntity<String> entity = new HttpEntity<>(mapper.writeValueAsString(body), headers);

        ResponseEntity<String> res = http.postForEntity(url, entity, String.class);
        JsonNode root = mapper.readTree(res.getBody());
        return root.path("choices").path(0)
                   .path("message").path("content").asText("");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // PARSING AND SANITIZATION
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Parses ---FILE:path:lang--- ... ---ENDFILE--- blocks
     * Same approach as Atul's parseFileBlocks() in JavaScript
     */
    private List<GeneratedFile> parseFileBlocks(String text) {
        List<GeneratedFile> files = new ArrayList<>();
        if (text == null || text.isBlank()) return files;

        Pattern p = Pattern.compile(
            "---FILE:([^:\\n]+):([^-\\n]+)---\\n?([\\s\\S]*?)---ENDFILE---"
        );
        Matcher m = p.matcher(text);
        while (m.find()) {
            String path     = m.group(1).trim();
            String language = m.group(2).trim();
            String content  = m.group(3).trim();
            if (!path.isEmpty() && !content.isEmpty()) {
                files.add(new GeneratedFile(path, language, content));
            }
        }

        // Fallback: if primary parser found nothing, try splitting on ---FILE:
        if (files.isEmpty()) {
            String[] segments = text.split("---FILE:");
            for (int i = 1; i < segments.length; i++) {
                String seg = segments[i];
                int headerEnd = seg.indexOf("---");
                if (headerEnd == -1) continue;
                String header = seg.substring(0, headerEnd).trim();
                int colon = header.lastIndexOf(":");
                if (colon == -1) continue;
                String path     = header.substring(0, colon).trim();
                String language = header.substring(colon + 1).trim();
                String body     = seg.substring(headerEnd + 3);
                int endIdx = body.indexOf("---ENDFILE---");
                if (endIdx != -1) body = body.substring(0, endIdx);
                body = body.trim();
                if (!path.isEmpty() && !body.isEmpty()) {
                    files.add(new GeneratedFile(path, language, body));
                }
            }
        }

        return files;
    }

    /** Parse the analysis JSON returned from Call 1 */
    @SuppressWarnings("unchecked")
    private Map<String, Object> parseAnalysisJson(String json) {
        try {
            // Strip markdown fences if AI wrapped it
            String clean = json.trim()
                .replaceAll("(?i)^```json\\s*", "")
                .replaceAll("\\s*```$", "")
                .replaceAll("(?i)^```\\s*", "");
            return mapper.readValue(clean, Map.class);
        } catch (Exception e) {
            System.err.println("Failed to parse analysis JSON: " + e.getMessage());
            // Return a basic fallback structure
            Map<String, Object> fallback = new HashMap<>();
            fallback.put("entities", List.of());
            fallback.put("operations", List.of("READ"));
            fallback.put("complexity", "Medium");
            fallback.put("confidenceScore", 70);
            fallback.put("migrationNotes", List.of("ABAP code analyzed"));
            fallback.put("warnings", List.of("Manual review recommended"));
            return fallback;
        }
    }

    /** Sanitize generated files — fix XML view issues */
    private List<GeneratedFile> sanitizeFiles(List<GeneratedFile> files) {
        return files.stream().map(file -> {
            if (file.path().endsWith(".xml")) {
                return new GeneratedFile(file.path(), file.language(),
                                         sanitizeXml(file.content()));
            }
            return file;
        }).toList();
    }

    /** Fix common AI mistakes in XML views — same concept as Atul's sanitizeHtml() */
    private String sanitizeXml(String xml) {
        if (xml == null) return "";
        String out = xml.trim();

        // Remove markdown code fences
        out = out.replaceAll("(?i)^```xml\\s*", "").replaceAll("\\s*```$", "");
        out = out.replaceAll("(?i)^```\\s*",    "").replaceAll("\\s*```$", "");

        // Fix wrong namespace for form — AI sometimes writes xmlns:f for form layout
        out = out.replace("xmlns:f=\"sap.ui.layout.form\"",
                          "xmlns:form=\"sap.ui.layout.form\"");
        // Fix f:SimpleForm → form:SimpleForm
        out = out.replace("<f:SimpleForm",  "<form:SimpleForm");
        out = out.replace("</f:SimpleForm>","</form:SimpleForm>");

        return out;
    }

    /** Extract the plain text message from chat response (after file blocks) */
    private String extractChatMessage(String raw, boolean noFiles) {
        if (raw == null) return "";
        if (noFiles) return raw.trim();

        // Find last ---ENDFILE--- and take text after it
        int lastEnd = raw.lastIndexOf("---ENDFILE---");
        if (lastEnd == -1) return "";
        String after = raw.substring(lastEnd + "---ENDFILE---".length()).trim();
        return after.isBlank() ? "Updated successfully!" : after;
    }

    // ══════════════════════════════════════════════════════════════════════════
    // PROMPT BUILDERS
    // ══════════════════════════════════════════════════════════════════════════

    private String buildGenerationPrompt(String analysisJson, String originalAbap) {
        return """
Generate a complete SAP CAP application from this ABAP analysis JSON.

ANALYSIS JSON:
%s

ORIGINAL ABAP (for reference — do NOT copy ABAP syntax, convert to CAP):
%s

IMPORTANT:
- Follow ALL blueprints in the system prompt exactly
- Return EXACTLY 8 ---FILE--- blocks
- Start immediately with ---FILE:db/schema.cds:cds---
- app/controller/Main.controller.js MUST have onSearch, onCreate, onItemPress with MessageToast
- app/view/Main.view.xml must use DynamicPage and show the main entity in a Table
- CSV header names MUST exactly match the XML binding paths (exact same case)
- Fill CSV with 5 rows of realistic mock data — every cell must have data, no empty cells
- The CSV file should be named data/db-<MainEntityName>.csv
""".formatted(analysisJson, originalAbap.substring(0, Math.min(originalAbap.length(), 1500)));
    }

    private String buildRetryPrompt(String analysisJson) {
        return """
Generate a SAP CAP application from this analysis. 
Start your response IMMEDIATELY with:
---FILE:db/schema.cds:cds---

Analysis:
%s

Return exactly 8 ---FILE--- blocks. No other text before the first block.
""".formatted(analysisJson);
    }

    private String buildChatUserMessage(ChatRequest req) {
        StringBuilder sb = new StringBuilder();
        sb.append(req.message()).append("\n");

        if (req.currentXml() != null && !req.currentXml().isBlank()) {
            sb.append("\nCurrent app/view/Main.view.xml (modify if needed):\n");
            sb.append(req.currentXml());
        }
        if (req.currentSchema() != null && !req.currentSchema().isBlank()) {
            sb.append("\n\nCurrent db/schema.cds (modify if needed):\n");
            sb.append(req.currentSchema());
        }
        if (req.currentCsv() != null && !req.currentCsv().isBlank()) {
            String csvPath = (req.currentCsvPath() != null && !req.currentCsvPath().isBlank())
                ? req.currentCsvPath() : "data/db-Entity.csv";
            sb.append("\n\nCurrent ").append(csvPath)
              .append(" — IMPORTANT: if you add/remove XML columns, you MUST return an updated CSV.\n")
              .append("CSV header names must EXACTLY match the XML binding paths (same case).\n")
              .append(req.currentCsv());
        }

        return sb.toString();
    }
}
