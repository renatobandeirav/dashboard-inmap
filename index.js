require("dotenv").config({ quiet: true });
const axios = require("axios");
const { vendedores, tecnicos } = require("./nome");

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
  const retorno = await buscar(
    "cliente_contrato",
    "cliente_contrato.id",
    idContrato,
    "1"
  );

  return retorno.registros?.[0] || null;
}

async function buscarCliente(idCliente) {
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

async function listarAtivacoesAgendadas() {
  const retornoOS = await buscar(
    "su_oss_chamado",
    "su_oss_chamado.id_assunto",
    "137",
    "100"
  );

  const ordens = retornoOS.registros || [];

  const agendadas = ordens.filter((os) => {
    return (
      os.status === "AG" &&
      os.id_tecnico !== "0" &&
      os.data_agenda &&
      os.data_agenda !== "0000-00-00 00:00:00"
    );
  });

  const resultado = [];

  for (const os of agendadas) {
    const contrato = await buscarContrato(os.id_contrato_kit);
    const cliente = await buscarCliente(os.id_cliente);

    const idVendedor =
      contrato?.id_vendedor ||
      cliente?.id_vendedor ||
      "";

    resultado.push({
      os: os.id,
      cliente: cliente?.razao || `Cliente ID ${os.id_cliente}`,
      vendedor_id: idVendedor,
      vendedor: vendedores[idVendedor] || `Vendedor ID ${idVendedor}`,
      tecnico_id: os.id_tecnico,
      tecnico: tecnicos[os.id_tecnico] || `Técnico ID ${os.id_tecnico}`,
      data_agenda: formatarDataHora(os.data_agenda),
      data_agenda_final: formatarDataHora(os.data_agenda_final),
      cidade_id: os.id_cidade,
      contrato: os.id_contrato_kit
    });
  }

  console.log("\nAtivações FTTH agendadas:");
  console.table(resultado);

  const resumoVendedores = resultado.reduce((acc, item) => {
    acc[item.vendedor] = (acc[item.vendedor] || 0) + 1;
    return acc;
  }, {});

  const resumoTecnicos = resultado.reduce((acc, item) => {
    acc[item.tecnico] = (acc[item.tecnico] || 0) + 1;
    return acc;
  }, {});

  console.log("\nResumo por vendedor:");
  console.table(
    Object.entries(resumoVendedores).map(([vendedor, quantidade]) => ({
      vendedor,
      quantidade
    }))
  );

  console.log("\nResumo por técnico:");
  console.table(
    Object.entries(resumoTecnicos).map(([tecnico, quantidade]) => ({
      tecnico,
      quantidade
    }))
  );
}

async function main() {
  try {
    await listarAtivacoesAgendadas();
  } catch (erro) {
    console.error("Erro na API:");
    console.error("Status:", erro.response?.status);
    console.error(erro.response?.data || erro.message);
  }
}

main();