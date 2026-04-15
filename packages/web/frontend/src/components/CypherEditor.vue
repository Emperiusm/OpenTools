<template>
  <div class="cypher-editor">
    <div ref="editorContainer" class="editor-container"></div>
    <div class="editor-actions">
      <button class="run-btn" @click="$emit('run')" :disabled="disabled">
        Run (Ctrl+Enter)
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, watch } from 'vue'
import { EditorView, keymap, placeholder } from '@codemirror/view'
import { EditorState } from '@codemirror/state'
import { defaultKeymap, history, historyKeymap } from '@codemirror/commands'
import { bracketMatching } from '@codemirror/language'
import { highlightSelectionMatches, searchKeymap } from '@codemirror/search'
import { autocompletion, completionKeymap } from '@codemirror/autocomplete'

const props = defineProps<{
  modelValue: string
  disabled?: boolean
}>()

const emit = defineEmits<{
  'update:modelValue': [value: string]
  run: []
}>()

const editorContainer = ref<HTMLElement>()
let view: EditorView | null = null

// Cypher keyword completions
const cypherCompletions = [
  // Keywords
  ...['MATCH', 'WHERE', 'RETURN', 'AND', 'OR', 'NOT', 'AS', 'IN', 'IS', 'NULL', 'FROM',
      'CONTAINS', 'STARTS WITH', 'ENDS WITH'].map(w => ({ label: w, type: 'keyword' })),
  // Node labels
  ...['Finding', 'Host', 'IP', 'CVE', 'Domain', 'Port', 'MitreAttack', 'Entity']
    .map(l => ({ label: l, type: 'type', detail: 'node label' })),
  // Edge labels
  ...['LINKED', 'MENTIONED_IN']
    .map(l => ({ label: l, type: 'type', detail: 'edge label' })),
  // Built-in functions
  ...['length', 'nodes', 'relationships', 'has_entity', 'has_mitre', 'collect']
    .map(f => ({ label: f, type: 'function' })),
  // Properties
  ...['severity', 'tool', 'title', 'weight', 'status', 'canonical_value', 'mention_count',
      'confidence', 'llm_rationale', 'llm_relation_type']
    .map(p => ({ label: p, type: 'property' })),
]

function cypherComplete(context: any) {
  const word = context.matchBefore(/[\w.]*/)
  if (!word || (word.from === word.to && !context.explicit)) return null
  return {
    from: word.from,
    options: cypherCompletions,
    validFor: /^[\w.]*$/,
  }
}

// Custom Cypher highlighting via simple syntax tag coloring
const cypherTheme = EditorView.theme({
  '&': { fontSize: '14px', fontFamily: "'Fira Code', 'Cascadia Code', monospace" },
  '.cm-content': { minHeight: '80px' },
  '.cm-gutters': { display: 'none' },
  '&.cm-focused': { outline: 'none' },
})

onMounted(() => {
  if (!editorContainer.value) return

  const runKeymap = keymap.of([{
    key: 'Ctrl-Enter',
    run: () => { emit('run'); return true },
  }, {
    key: 'Cmd-Enter',
    run: () => { emit('run'); return true },
  }])

  const startState = EditorState.create({
    doc: props.modelValue,
    extensions: [
      runKeymap,
      keymap.of([...defaultKeymap, ...historyKeymap, ...searchKeymap, ...completionKeymap]),
      history(),
      bracketMatching(),
      highlightSelectionMatches(),
      autocompletion({ override: [cypherComplete] }),
      placeholder('MATCH (a:Finding)-[r:LINKED]->(b:Finding) RETURN a, b'),
      cypherTheme,
      EditorView.lineWrapping,
      EditorView.editable.of(!props.disabled),
      EditorView.updateListener.of((update) => {
        if (update.docChanged) {
          emit('update:modelValue', update.state.doc.toString())
        }
      }),
      EditorState.readOnly.of(!!props.disabled),
    ],
  })

  view = new EditorView({
    state: startState,
    parent: editorContainer.value,
  })
})

onUnmounted(() => {
  view?.destroy()
  view = null
})

watch(() => props.modelValue, (newVal) => {
  if (view && view.state.doc.toString() !== newVal) {
    view.dispatch({
      changes: { from: 0, to: view.state.doc.length, insert: newVal },
    })
  }
})

// Disabled state is set at mount time via EditorView.editable.
// Dynamic toggling during a query run is brief enough that rebuilding
// the editor isn't needed — the Run button is already disabled.
</script>

<style scoped>
.cypher-editor {
  display: flex;
  flex-direction: column;
  border: 1px solid var(--border-color, #ddd);
  border-radius: 4px;
  overflow: hidden;
}
.editor-container {
  min-height: 80px;
  max-height: 200px;
  overflow: auto;
}
.editor-actions {
  display: flex;
  justify-content: flex-end;
  padding: 4px 8px;
  border-top: 1px solid var(--border-color, #ddd);
  background: #f8f8f8;
}
.run-btn {
  padding: 4px 12px;
  cursor: pointer;
  background: #2196F3;
  color: white;
  border: none;
  border-radius: 3px;
  font-size: 12px;
}
.run-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
</style>
