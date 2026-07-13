function criarAgendadorPiperun({
  sincronizarPerdidos,
  intervaloMs = 10 * 60 * 1000,
  atrasoInicialMs = 30 * 1000
}) {
  if (typeof sincronizarPerdidos !== "function") {
    throw new Error(
      "A função sincronizarPerdidos é obrigatória no agendador Piperun."
    );
  }

  let sincronizacaoEmAndamento = false;
  let timerIntervalo = null;
  let timerInicial = null;

  async function executarSincronizacaoAutomatica() {
    if (sincronizacaoEmAndamento) {
      console.warn(
        "[PIPERUN] Sincronização ignorada porque outra execução ainda está em andamento."
      );
      return;
    }

    sincronizacaoEmAndamento = true;
    const inicio = Date.now();

    try {
      console.log("[PIPERUN] Iniciando sincronização automática...");

      const resultado = await sincronizarPerdidos({
        show: 100
      });

      console.log("[PIPERUN] Sincronização concluída.", {
        recebidos: resultado.recebidos,
        tratados: resultado.tratados,
        salvos: resultado.salvos,
        total_paginas: resultado.total_paginas,
        duracao_ms: Date.now() - inicio,
        data_hora: new Date().toISOString()
      });
    } catch (erro) {
      console.error("[PIPERUN] Erro na sincronização automática.", {
        mensagem: erro?.message || "Erro desconhecido",
        status_externo: erro?.status || null,
        duracao_ms: Date.now() - inicio,
        data_hora: new Date().toISOString()
      });
    } finally {
      sincronizacaoEmAndamento = false;
    }
  }

  function iniciar() {
    if (timerIntervalo || timerInicial) {
      console.warn("[PIPERUN] Agendador já está ativo.");
      return;
    }

    console.log("[PIPERUN] Agendador iniciado.", {
      intervalo_minutos: intervaloMs / 60000,
      primeira_execucao_segundos: atrasoInicialMs / 1000
    });

    timerInicial = setTimeout(async () => {
      timerInicial = null;

      await executarSincronizacaoAutomatica();

      timerIntervalo = setInterval(
        executarSincronizacaoAutomatica,
        intervaloMs
      );
    }, atrasoInicialMs);
  }

  function parar() {
    if (timerInicial) {
      clearTimeout(timerInicial);
      timerInicial = null;
    }

    if (timerIntervalo) {
      clearInterval(timerIntervalo);
      timerIntervalo = null;
    }

    console.log("[PIPERUN] Agendador interrompido.");
  }

  return {
    iniciar,
    parar,
    executarAgora: executarSincronizacaoAutomatica
  };
}

module.exports = {
  criarAgendadorPiperun
};