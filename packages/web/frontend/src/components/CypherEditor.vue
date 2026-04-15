<!-- packages/web/frontend/src/components/CypherEditor.vue -->
<template>
  <div class="cypher-editor">
    <textarea
      ref="editorRef"
      v-model="localValue"
      class="editor-textarea"
      placeholder="MATCH (a:Finding)-[r:LINKED]->(b:Finding) RETURN a, b"
      :disabled="disabled"
      @keydown.ctrl.enter.prevent="$emit('run')"
      @keydown.meta.enter.prevent="$emit('run')"
    ></textarea>
    <div class="editor-actions">
      <button class="run-btn" @click="$emit('run')" :disabled="disabled">
        Run (Ctrl+Enter)
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'

const props = defineProps<{
  modelValue: string
  disabled?: boolean
}>()

const emit = defineEmits<{
  'update:modelValue': [value: string]
  run: []
}>()

const localValue = ref(props.modelValue)

watch(() => props.modelValue, (v) => { localValue.value = v })
watch(localValue, (v) => { emit('update:modelValue', v) })
</script>

<style scoped>
.cypher-editor {
  display: flex;
  flex-direction: column;
  border: 1px solid var(--border-color, #ddd);
  border-radius: 4px;
}
.editor-textarea {
  min-height: 100px;
  max-height: 200px;
  padding: 8px;
  font-family: 'Fira Code', 'Cascadia Code', monospace;
  font-size: 14px;
  border: none;
  outline: none;
  resize: vertical;
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
}
.run-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
</style>
