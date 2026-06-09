require("dotenv").config({ quiet: true });
const express = require("express");
const axios = require("axios");
const { vendedores, tecnicos } = require("./nome");
const path = require("path");

const app = express();
app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

const PORT = 3000;

const assuntosMonitorados = {
  "137": "ATIVAÇÃO FTTH",
  "599": "REATIVAÇÃO 90 DIAS",
  "591": "REATIVAÇÃO COMERCIAL"
};

const tokenBase64 = Buffer.from(process.env.IXC_TOKEN).toString("base64");

const api = axios.create({
  baseURL: process.env.IXC_URL,
  headers: {
    Authorization: `Basic ${tokenBase64}`,
    "Content-Type": "application/json",
    ixcsoft: "listar"
  }
});

async function buscar(endpoint, qtype, query, rp = "50") {
  const params = {
    qtype,
    query,
    oper: "=",
    page: "1",
    rp,
    sortname: "id",
    sortorder: "desc"
  };

  const response = await api.post(`/${endpoint}`, params);
  return response.data;
}

async function buscarContrato(idContrato) {
  if (!idContrato || idContrato === "0") return null;

  const retorno = await buscar(
    "cliente_contrato",
    "cliente_contrato.id",
    idContrato,
    "1"
  );

  return retorno.registros?.[0] || null;
}

async function buscarCliente(idCliente) {
  if (!idCliente || idCliente === "0") return null;

  const retorno = await buscar(
    "cliente",
    "cliente.id",
    idCliente,
    "1"
  );

  return retorno.registros?.[0] || null;
}

function formatarDataHora(dataHora) {
  if (!dataHora || dataHora === "0000-00-00 00:00:00") return "";

  const [data, hora] = dataHora.split(" ");
  const [ano, mes, dia] = data.split("-");

  return `${dia}/${mes}/${ano} ${hora?.slice(0, 5) || ""}`;
}

function converterDataBRParaOrdenacao(dataHoraBR) {
  if (!dataHoraBR) return new Date(0);

  const [data, hora] = dataHoraBR.split(" ");
  const [dia, mes, ano] = data.split("/");

  return new Date(`${ano}-${mes}-${dia}T${hora || "00:00"}`);
}

function classificarOS(os) {
  if (os.status === "A" && os.id_tecnico === "0") {
    return "O.S. DE ATIVAÇÃO ABERTA";
  }

  if (os.status === "A") {
    return "O.S. ABERTA";
  }

  if (os.status === "AG") {
    return "AGENDADA";
  }

    if (os.status === "EX") {
      return "EXECUÇÃO";
    }

    if (os.status === "RAG") {
      return "AGUARDANDO REAGENDAMENTO";
    }

    if (os.status === "R") {
      return "REAGENDADA";
    }

  if (os.status === "F") {
    return "FINALIZADA";
  }

  return `STATUS ${os.status}`;
}

function classificarGrade(dataAgenda) {
  if (!dataAgenda || dataAgenda === "0000-00-00 00:00:00") {
    return "SEM DATA DE AGENDA";
  }

  const dataOS = new Date(dataAgenda.replace(" ", "T"));

  const hoje = new Date();
  hoje.setHours(0, 0, 0, 0);

  const amanha = new Date(hoje);
  amanha.setDate(hoje.getDate() + 1);

  const depoisDeAmanha = new Date(hoje);
  depoisDeAmanha.setDate(hoje.getDate() + 2);

  if (dataOS >= hoje && dataOS < amanha) {
    return "GRADE DE HOJE";
  }

  if (dataOS >= amanha && dataOS < depoisDeAmanha) {
    return "GRADE DO DIA SEGUINTE";
  }

  if (dataOS >= depoisDeAmanha) {
    return "AGENDA FUTURA";
  }

  return "AGENDA ANTERIOR";
}

function gerarResumo(lista, campo) {
  return Object.entries(
    lista.reduce((acc, item) => {
      acc[item[campo]] = (acc[item[campo]] || 0) + 1;
      return acc;
    }, {})
  ).map(([nome, quantidade]) => ({
    nome,
    quantidade
  }));
}

async function listarOrdensMonitoradas() {
  const resultado = [];

  for (const idAssunto of Object.keys(assuntosMonitorados)) {
    const retornoOS = await buscar(
      "su_oss_chamado",
      "su_oss_chamado.id_assunto",
      idAssunto,
      "200"
    );

    const ordens = retornoOS.registros || [];

    function ehHoje(dataHora) {
  if (!dataHora || dataHora === "0000-00-00 00:00:00") return false;

  const data = new Date(dataHora.replace(" ", "T"));

  const hoje = new Date();
  hoje.setHours(0, 0, 0, 0);

  const amanha = new Date(hoje);
  amanha.setDate(hoje.getDate() + 1);

  return data >= hoje && data < amanha;
}

const ordensValidas = ordens.filter((os) => {
  const situacao = classificarOS(os);

  const grade =
    os.status === "RAG"
      ? "AGUARDANDO NOVA DATA"
      : classificarGrade(os.data_agenda);

  const osAbertaParaAgendar =
    situacao === "O.S. DE ATIVAÇÃO ABERTA";

  const osAgendadaAtualOuFutura =
    ["GRADE DE HOJE", "GRADE DO DIA SEGUINTE", "AGENDA FUTURA"].includes(grade);

  const osEmExecucao =
    situacao === "EXECUÇÃO";

  const osAguardandoReagendamento =
    situacao === "AGUARDANDO REAGENDAMENTO";

  const osReagendadaAtualOuFutura =
    situacao === "REAGENDADA" &&
    ["GRADE DE HOJE", "GRADE DO DIA SEGUINTE", "AGENDA FUTURA"].includes(grade);

  const osFinalizadaHoje =
    situacao === "FINALIZADA" &&
    ehHoje(os.data_fechamento || os.data_final || os.ultima_atualizacao);

  return (
    osAbertaParaAgendar ||
    osAgendadaAtualOuFutura ||
    osEmExecucao ||
    osAguardandoReagendamento ||
    osReagendadaAtualOuFutura ||
    osFinalizadaHoje
  );
});


    for (const os of ordensValidas) {
      const contrato = await buscarContrato(os.id_contrato_kit);
      const cliente = await buscarCliente(os.id_cliente);

      const idVendedor =
        contrato?.id_vendedor ||
        cliente?.id_vendedor ||
        "";

      resultado.push({
        tipo_os: assuntosMonitorados[os.id_assunto] || `Assunto ID ${os.id_assunto}`,
        assunto_id: os.id_assunto,
        situacao_os: classificarOS(os),
       grade:
        os.status === "RAG"
        ? "AGUARDANDO NOVA DATA"
        : classificarGrade(os.data_agenda),
        os: os.id,
        cliente: cliente?.razao || `Cliente ID ${os.id_cliente}`,
        vendedor_id: idVendedor,
        vendedor: vendedores[idVendedor] || `Vendedor ID ${idVendedor}`,
        tecnico_id: os.id_tecnico,
        tecnico:
          os.id_tecnico === "0"
            ? classificarOS(os)
            : tecnicos[os.id_tecnico] || `Técnico ID ${os.id_tecnico}`,
        data_agenda: formatarDataHora(os.data_agenda),
        data_agenda_final: formatarDataHora(os.data_agenda_final),
        data_reagendar: formatarDataHora(os.data_reagendar),
        cidade_id: os.id_cidade,
        contrato: os.id_contrato_kit,
        status: os.status
      });
    }
  }

  resultado.sort((a, b) => {
    const dataA = converterDataBRParaOrdenacao(a.data_agenda);
    const dataB = converterDataBRParaOrdenacao(b.data_agenda);
    return dataA - dataB;
  });

  return {
    total: resultado.length,
    ordens: resultado,
    ativacoes: resultado,
    resumo_situacoes: gerarResumo(resultado, "situacao_os"),
    resumo_grades: gerarResumo(resultado, "grade"),
    resumo_vendedores: gerarResumoPorVendedor(resultado),
    resumo_tecnicos: gerarResumo(resultado, "tecnico"),
    resumo_tipos: gerarResumo(resultado, "tipo_os")
  };
}

function gerarResumoPorVendedor(lista) {
  const resumo = {};

  for (const item of lista) {
    if (!resumo[item.vendedor]) {
      resumo[item.vendedor] = {
        vendedor: item.vendedor,
        grade_hoje: 0,
        grade_dia_seguinte: 0,
        instalados_dia: 0,
        reagendados_dia: 0,
        finalizadas_dia: 0
      };
    }

    if (item.situacao_os === "AGENDADA" && item.grade === "GRADE DE HOJE") {
      resumo[item.vendedor].grade_hoje += 1;
    }

    if (item.situacao_os === "AGENDADA" && item.grade === "GRADE DO DIA SEGUINTE") {
      resumo[item.vendedor].grade_dia_seguinte += 1;
    }

    if (item.situacao_os === "EXECUÇÃO") {
      resumo[item.vendedor].instalados_dia += 1;
    }

    if (
      item.situacao_os === "REAGENDADA" ||
      item.situacao_os === "AGUARDANDO REAGENDAMENTO"
    ) {
      resumo[item.vendedor].reagendados_dia += 1;
    }

    if (item.situacao_os === "FINALIZADA") {
      resumo[item.vendedor].finalizadas_dia += 1;
    }
  }

  return Object.values(resumo);
}

app.get("/api/ativacoes", async (req, res) => {
  try {
    const dados = await listarOrdensMonitoradas();
    res.json(dados);
  } catch (erro) {
    res.status(500).json({
      erro: true,
      status: erro.response?.status || null,
      mensagem: erro.response?.data || erro.message
    });
  }
});

app.get("/api/ativacoes", async (req, res) => {
  try {
    const dados = await listarOrdensMonitoradas();
    res.json(dados);
  } catch (erro) {
    res.status(500).json({
      erro: true,
      status: erro.response?.status || null,
      mensagem: erro.response?.data || erro.message
    });
  }
});

app.get("/api/debug", async (req, res) => {
  try {
    const retorno = await buscar(
      "su_oss_chamado",
      "su_oss_chamado.id_assunto",
      "137",
      "5"
    );

    res.json(retorno);
  } catch (erro) {
    res.status(500).json({
      erro: true,
      mensagem: erro.response?.data || erro.message
    });
  }
});

module.exports = app;