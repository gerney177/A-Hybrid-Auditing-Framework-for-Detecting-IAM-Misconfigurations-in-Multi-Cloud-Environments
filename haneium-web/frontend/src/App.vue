<script setup lang="ts">
import { onMounted } from 'vue'
import AppSidebar from '@/components/AppSidebar.vue'
import ToastHost from '@/components/ToastHost.vue'
import { useAnalysis } from '@/stores/analysis'

const store = useAnalysis()
onMounted(() => store.load())
</script>

<template>
  <div class="min-h-screen lg:grid lg:grid-cols-[248px_minmax(0,1fr)]">
    <AppSidebar />
    <main class="mx-auto w-full max-w-[1320px] px-4 py-6 sm:px-8 lg:py-9">
      <RouterView v-slot="{ Component }">
        <Transition name="fade" mode="out-in">
          <component :is="Component" />
        </Transition>
      </RouterView>
    </main>
    <ToastHost />
  </div>
</template>
